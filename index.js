const express = require("express");
const cors = require("cors");
const snmp = require("net-snmp");
const mysql = require("mysql2/promise");
const http = require("http");
const { Server } = require("socket.io");
const ping = require("ping");
const { config } = require("dotenv");

config()

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

/* ================= MYSQL ================= */
const db = mysql.createPool({
  host: "127.0.0.1",
  user: "root",
  password: "",
  database: "nms",
});

/* ================= OIDS ================= */
const OIDS = {
  ifDescr: "1.3.6.1.2.1.2.2.1.2",
  ifName: "1.3.6.1.2.1.31.1.1.1.1",
  ifType: "1.3.6.1.2.1.2.2.1.3",
  ifSpeed: "1.3.6.1.2.1.2.2.1.5",
  ifAdmin: "1.3.6.1.2.1.2.2.1.7",
  ifOper: "1.3.6.1.2.1.2.2.1.8",
  ifIn: "1.3.6.1.2.1.2.2.1.10",
  ifOut: "1.3.6.1.2.1.2.2.1.16",
};

/* ================= STATE ================= */
const lastCounters = {};
const liveTraffic = {};

/* ================= SAFE SNMP WALK ================= */
function snmpWalk(session, oid) {
  return new Promise((resolve) => {
    const results = [];

    session.subtree(
      oid,
      (varbinds) => {
        if (Array.isArray(varbinds)) {
          varbinds.forEach((vb) => {
            if (!snmp.isVarbindError(vb)) results.push(vb);
          });
        } else if (!snmp.isVarbindError(varbinds)) {
          results.push(varbinds);
        }
      },
      (err) => {
        if (err) {
          console.warn("SNMP walk failed:", oid, err.message);
          return resolve([]); // ⬅️ DO NOT CRASH
        }
        resolve(results);
      }
    );
  });
}

/* ================= POLL DEVICE ================= */
async function pollDevice(device) {
  const now = Date.now();

  try {
    const pingRes = await ping.promise.probe(device.ip, { timeout: 2 });

    await db.query("UPDATE devices SET status=? WHERE id=?", [
      pingRes.alive ? "UP" : "DOWN",
      device.id,
    ]);

    if (!pingRes.alive) return;

    const session = snmp.createSession(device.ip, device.community, {
      version: snmp.Version2c,
      timeout: 2000,   // ⬅️ increased
      retries: 2,      // ⬅️ retries
    });

    if (!lastCounters[device.id]) lastCounters[device.id] = {};
    if (!liveTraffic[device.id]) liveTraffic[device.id] = {};

    const [
      descrs,
      names,
      types,
      speeds,
      admins,
      opers,
    ] = await Promise.all([
      snmpWalk(session, OIDS.ifDescr),
      snmpWalk(session, OIDS.ifName),
      snmpWalk(session, OIDS.ifType),
      snmpWalk(session, OIDS.ifSpeed),
      snmpWalk(session, OIDS.ifAdmin),
      snmpWalk(session, OIDS.ifOper),
    ]);

    const map = {};
    const add = (arr, key) =>
      arr.forEach((v) => {
        const idx = Number(v.oid.split(".").pop());
        map[idx] = map[idx] || {};
        map[idx][key] = v.value;
      });

    add(descrs, "ifDescr");
    add(names, "ifName");
    add(types, "ifType");
    add(speeds, "ifSpeed");
    add(admins, "ifAdminStatus");
    add(opers, "ifOperStatus");

    for (const ifIndex in map) {
      const i = map[ifIndex];

      await db.query(
        `INSERT INTO interfaces
        (device_id, ifIndex, ifDescr, ifName, ifType, ifSpeed, ifAdminStatus, ifOperStatus, last_polled)
        VALUES (?,?,?,?,?,?,?,?,NOW())
        ON DUPLICATE KEY UPDATE
        ifDescr=VALUES(ifDescr),
        ifName=VALUES(ifName),
        ifType=VALUES(ifType),
        ifSpeed=VALUES(ifSpeed),
        ifAdminStatus=VALUES(ifAdminStatus),
        ifOperStatus=VALUES(ifOperStatus),
        last_polled=NOW()`,
        [
          device.id,
          ifIndex,
          i.ifDescr?.toString() || "",
          i.ifName?.toString() || "",
          i.ifType || 0,
          i.ifSpeed || 0,
          i.ifAdminStatus || 0,
          i.ifOperStatus || 0,
        ]
      );

      if (!lastCounters[device.id][ifIndex]) {
        lastCounters[device.id][ifIndex] = { in: 0, out: 0, t: now };
        liveTraffic[device.id][ifIndex] = { rx: 0, tx: 0 };
      }
    }

    const ins = await snmpWalk(session, OIDS.ifIn);
    const outs = await snmpWalk(session, OIDS.ifOut);

    ins.forEach((v) => {
      const idx = Number(v.oid.split(".").pop());
      const prev = lastCounters[device.id][idx];
      if (!prev) return;

      const dt = (now - prev.t) / 1000 || 1;
      liveTraffic[device.id][idx].rx =
        Math.max(((Number(v.value) - prev.in) * 8) / dt, 0);

      prev.in = Number(v.value);
      prev.t = now;
    });

    outs.forEach((v) => {
      const idx = Number(v.oid.split(".").pop());
      const prev = lastCounters[device.id][idx];
      if (!prev) return;

      const dt = (now - prev.t) / 1000 || 1;
      liveTraffic[device.id][idx].tx =
        Math.max(((Number(v.value) - prev.out) * 8) / dt, 0);

      prev.out = Number(v.value);
      prev.t = now;
    });

    session.close();
  } catch (err) {
    console.error(`Poll failed for ${device.ip}:`, err.message);
  }
}

/* ================= POLL LOOP ================= */
setInterval(async () => {
  try {
    const [devices] = await db.query("SELECT * FROM devices");
    for (const d of devices) await pollDevice(d);
    io.emit("traffic", liveTraffic);
  } catch (err) {
    console.error("Polling loop error:", err.message);
  }
}, 1000);

/* ================= API ================= */
app.get("/api/devices", async (req, res) => {
  const [devices] = await db.query("SELECT * FROM devices");
  const [interfaces] = await db.query(`
    SELECT i.*, d.name AS device_name
    FROM interfaces i
    JOIN devices d ON d.id=i.device_id
  `);
  res.json({ devices, interfaces });
});

/* ================= START ================= */
server.listen(5000, () =>
  console.log("Backend running on http://localhost:5000")
);

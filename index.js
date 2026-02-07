const express = require("express");
const cors = require("cors");
const snmp = require("net-snmp");
const mysql = require("mysql2/promise");
const http = require("http");
const { Server } = require("socket.io");
const ping = require("ping");
const { config } = require("dotenv");
const TelegramBot = require('node-telegram-bot-api');  // New: For Telegram
const dns = require('dns').promises;
const telegramManager = require('./telegramManager');

config();

const app = express();
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') res.sendStatus(200);
  else next();
});
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

/* ================= MYSQL ================= */

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

/* ================= OIDS ================= */
const OIDS = {
  sysName: "1.3.6.1.2.1.1.5.0",
  ifDescr: "1.3.6.1.2.1.2.2.1.2",
  ifName: "1.3.6.1.2.1.31.1.1.1.1",
  ifAlias: "1.3.6.1.2.1.31.1.1.1.18",  // Added for user-set description/alias
  ifType: "1.3.6.1.2.1.2.2.1.3",
  ifSpeed: "1.3.6.1.2.1.2.2.1.5",
  ifAdmin: "1.3.6.1.2.1.2.2.1.7",
  ifOper: "1.3.6.1.2.1.2.2.1.8",
  ifIn: "1.3.6.1.2.1.2.2.1.10",
  ifOut: "1.3.6.1.2.1.2.2.1.16",
  ifInErrors: "1.3.6.1.2.1.2.2.1.14",
  ifOutErrors: "1.3.6.1.2.1.2.2.1.20",
  ifInDiscards: "1.3.6.1.2.1.2.2.1.13",
  ifOutDiscards: "1.3.6.1.2.1.2.2.1.19",
};

/* ================= STATE ================= */
const lastCounters = {};
const liveTraffic = {};
const previousStatuses = {};  // Track previous port statuses for change detection
const previousDeviceStatuses = {};  // New: Track previous device statuses for change detection

/* ================= TELEGRAM SETUP ================= */
const botToken = process.env.TELEGRAM_BOT_TOKEN;
const chatId = process.env.TELEGRAM_CHAT_ID;
let bot;
if (botToken) {
  bot = new TelegramBot(botToken, { polling: false });
} else {
  console.warn('Telegram bot token not set. Notifications disabled.');
}

/* ================= SAFE SNMP GET ================= */
function snmpGet(session, oid) {
  return new Promise((resolve) => {
    session.get([oid], (err, varbinds) => {
      if (err || !varbinds || snmp.isVarbindError(varbinds[0])) {
        console.warn("SNMP get failed:", oid, err?.message || "No data");
        return resolve(null);
      }
      resolve(varbinds[0].value);
    });
  });
}

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
          return resolve([]);
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
    const pingRes = await ping.promise.probe(device.ip_address, { timeout: 30 });

    const currentDeviceStatus = pingRes.alive ? "UP" : "DOWN";

    // Fixed: Check for device status change and send Telegram alert (corrected typo: !==  -> !== undefined)
    if (previousDeviceStatuses[device.id] !== undefined && previousDeviceStatuses[device.id] !== currentDeviceStatus && bot) {
      const alertMessage = `Alert: Device ${device.hostname || device.ip_address} (${device.ip_address}) is now ${currentDeviceStatus}.`;
      bot.sendMessage(chatId, alertMessage).catch(err => console.error('Telegram send failed:', err));
    }
    previousDeviceStatuses[device.id] = currentDeviceStatus;

    await db.query("UPDATE devices SET status=? WHERE id=?", [
      currentDeviceStatus,
      device.id,
    ]);

    if (!pingRes.alive) {
      // Device unreachable: Set all ports to DOWN (2)
      const [interfaces] = await db.query("SELECT ifIndex FROM interfaces WHERE device_id = ?", [device.id]);
      interfaces.forEach(iface => {
        if (!liveTraffic[device.id]) liveTraffic[device.id] = {};
        liveTraffic[device.id][iface.ifIndex] = { status: 2 }; // DOWN
        // New: Update previous port statuses to DOWN
        if (!previousStatuses[device.id]) previousStatuses[device.id] = {};
        previousStatuses[device.id][iface.ifIndex] = 2;
      });
      // Alert already sent above for device DOWN
      console.log(`Device ${device.ip_address} unreachable: All ports set to DOWN`);
      return;
    }

    // Device reachable: Poll interfaces
    const session = snmp.createSession(device.ip_address, device.snmp_community, {
      version: snmp.Version2c,
      timeout: 2000,
      retries: 2,
    });

    if (!lastCounters[device.id]) lastCounters[device.id] = {};
    if (!liveTraffic[device.id]) liveTraffic[device.id] = {};
    if (!previousStatuses[device.id]) previousStatuses[device.id] = {};  // Init previous statuses

    // Poll sysName and update hostname
    const sysName = await snmpGet(session, OIDS.sysName);
    if (sysName && sysName.toString() !== device.hostname) {
      await db.query("UPDATE devices SET hostname=? WHERE id=?", [
        sysName.toString(),
        device.id,
      ]);
    }

    // Poll CPU usage (try multiple OIDs)
    let cpuUsage = null;
    const cpuOids = [
      // "1.3.6.1.4.1.9.2.1.58.0",
      // "1.3.6.1.4.1.2011.6.1.1.1.1.6.0",
      // "1.3.6.1.2.1.25.3.3.1.2.1",
    ];
    for (const oid of cpuOids) {
      cpuUsage = await snmpGet(session, oid);
      if (cpuUsage !== null) break;
    }
    if (cpuUsage !== null) {
      await db.query("UPDATE devices SET cpu_usage=? WHERE id=?", [
        parseFloat(cpuUsage),
        device.id,
      ]);
    } else {
      console.warn(`No CPU OID worked for ${device.ip_address}`);
    }

    // Poll interface data (added ifAlias, ifInOctets, ifOutOctets)
    const [
      descrs,
      names,
      aliases,
      types,
      speeds,
      admins,
      opers,
      inErrors,
      outErrors,
      inDiscards,
      outDiscards,
      inOctets,  // New: Poll raw inbound octets
      outOctets, // New: Poll raw outbound octets
    ] = await Promise.all([
      snmpWalk(session, OIDS.ifDescr),
      snmpWalk(session, OIDS.ifName),
      snmpWalk(session, OIDS.ifAlias),
      snmpWalk(session, OIDS.ifType),
      snmpWalk(session, OIDS.ifSpeed),
      snmpWalk(session, OIDS.ifAdmin),
      snmpWalk(session, OIDS.ifOper),
      snmpWalk(session, OIDS.ifInErrors),
      snmpWalk(session, OIDS.ifOutErrors),
      snmpWalk(session, OIDS.ifInDiscards),
      snmpWalk(session, OIDS.ifOutDiscards),
      snmpWalk(session, OIDS.ifIn),  // New: Poll ifInOctets
      snmpWalk(session, OIDS.ifOut), // New: Poll ifOutOctets
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
    add(aliases, "ifAlias");
    add(types, "ifType");
    add(speeds, "ifSpeed");
    add(admins, "ifAdminStatus");
    add(opers, "ifOperStatus");
    add(inErrors, "ifInErrors");
    add(outErrors, "ifOutErrors");
    add(inDiscards, "ifInDiscards");
    add(outDiscards, "ifOutDiscards");
    add(inOctets, "ifInOctets");  // New: Add to map
    add(outOctets, "ifOutOctets"); // New: Add to map

    for (const ifIndex in map) {
      const i = map[ifIndex];

      await db.query(
        `INSERT INTO interfaces
        (device_id, ifIndex, ifDescr, ifName, ifAlias, ifType, ifSpeed, ifAdminStatus, ifOperStatus, ifInErrors, ifOutErrors, ifInDiscards, ifOutDiscards, ifInOctets, ifOutOctets, last_polled)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())
        ON DUPLICATE KEY UPDATE
        ifDescr=VALUES(ifDescr),
        ifName=VALUES(ifName),
        ifAlias=VALUES(ifAlias),
        ifType=VALUES(ifType),
        ifSpeed=VALUES(ifSpeed),
        ifAdminStatus=VALUES(ifAdminStatus),
        ifOperStatus=VALUES(ifOperStatus),
        ifInErrors=VALUES(ifInErrors),
        ifOutErrors=VALUES(ifOutErrors),
        ifInDiscards=VALUES(ifInDiscards),
        ifOutDiscards=VALUES(ifOutDiscards),
        ifInOctets=VALUES(ifInOctets),
        ifOutOctets=VALUES(ifOutOctets),
        last_polled=NOW()`,
        [
          device.id,
          ifIndex,
          i.ifDescr?.toString() || "",
          i.ifName?.toString() || "",
          i.ifAlias?.toString() || "",
          i.ifType || 0,
          i.ifSpeed || 0,
          i.ifAdminStatus || 0,
          i.ifOperStatus || 0,
          i.ifInErrors || 0,
          i.ifOutErrors || 0,
          i.ifInDiscards || 0,
          i.ifOutDiscards || 0,
          i.ifInOctets || 0,  // New: Store raw inbound octets
          i.ifOutOctets || 0, // New: Store raw outbound octets
        ]
      );

      if (!lastCounters[device.id][ifIndex]) {
        lastCounters[device.id][ifIndex] = { in: 0, out: 0, t: now };
        liveTraffic[device.id][ifIndex] = { rx: 0, tx: 0 };
      }
    }

    // Poll traffic counters (unchanged - for rate calculation)
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

    // Poll ifOperStatus for status (1 = UP, 2 = DOWN)
    const operStatuses = await snmpWalk(session, OIDS.ifOper);

    operStatuses.forEach((v) => {
      const idx = Number(v.oid.split(".").pop());
      const status = Number(v.value); // 1 = UP, 2 = DOWN
      liveTraffic[device.id][idx] = { ...liveTraffic[device.id][idx], status };

      // Fixed: Check for status change and send Telegram alert
      const prevStatus = previousStatuses[device.id][idx];
      if (prevStatus !== undefined && prevStatus !== status && bot) {
        const statusText = status === 1 ? 'UP' : 'DOWN';
        const portName = map[idx]?.ifDescr?.toString() || idx;  // Use ifDescr if available, else idx
        const alertMessage = `Alert: Port ${portName} on Device ${device.hostname || device.ip_address} is now ${statusText}`;
        bot.sendMessage(chatId, alertMessage).catch(err => console.error('Telegram send failed:', err));
      }
      // Update previous status
      previousStatuses[device.id][idx] = status;

      console.log(`Device ${device.ip_address}, Port ${idx}: Status = ${status} (${status === 1 ? 'UP' : 'DOWN'})`);
    });

    session.close();
  } catch (err) {
    console.error(`Poll failed for ${device.ip_address}:`, err.message);
    // On error, assume DOWN (2)
    const [interfaces] = await db.query("SELECT ifIndex FROM interfaces WHERE device_id = ?", [device.id]);
    interfaces.forEach(iface => {
      if (!liveTraffic[device.id]) liveTraffic[device.id] = {};
      liveTraffic[device.id][iface.ifIndex] = { status: 2 };
      // New: Update previous port statuses to DOWN
      if (!previousStatuses[device.id]) previousStatuses[device.id] = {};
      previousStatuses[device.id][iface.ifIndex] = 2;
    });
  }
}

/* ================= POLL LOOP ================= */
let polling = false;  // Flag to prevent overlapping polls
setInterval(async () => {
  //if (polling) return;  // Skip if previous poll is still running
  //polling = true;
  try {
    const [devices] = await db.query("SELECT * FROM devices");
    for (const d of devices) await pollDevice(d);
    io.emit("traffic", liveTraffic);
  } catch (err) {
    console.error("Polling loop error:", err.message);
    // New: Send Telegram alert for polling errors
    if (bot) {
      bot.sendMessage(chatId, `Error: Polling loop failed - ${err.message}`).catch(err => console.error('Telegram send failed:', err));
    }
  }
  //polling = false;
}, 60000);

/* ================= API ================= */
app.get("/api/devices", async (req, res) => {
  const [devices] = await db.query("SELECT * FROM devices");
  const [interfaces] = await db.query(`
    SELECT i.*, d.hostname AS device_name
    FROM interfaces i
    JOIN devices d ON d.id=i.device_id
  `);
  res.json({ devices, interfaces });
});

app.post("/api/devices", async (req, res) => {
  const { hostname, ip_address, snmp_version, snmp_community, options } = req.body;

  // Basic validation
  if (!hostname || !ip_address || !snmp_community || !options) {
    return res.status(400).json({ error: "Hostname, IP address, and SNMP community are required." });
  }

  try {
    // Check if IP already exists
    const [existing] = await db.query("SELECT id FROM devices WHERE ip_address = ?", [ip_address]);
    if (existing.length > 0) {
      return res.status(409).json({ error: "Device with this IP address already exists." });
    }

    // Insert new device
    const [result] = await db.query(
      "INSERT INTO devices (hostname, ip_address, snmp_version, snmp_community, options) VALUES (?, ?, ?, ?, ?)",
      [hostname, ip_address, snmp_version || '2c', snmp_community, options]
    );

    res.status(201).json({ message: "Device added successfully", deviceId: result.insertId });
  } catch (err) {
    console.error("Error adding device:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

/* ================= UPDATE DEVICE ================= */
app.put("/api/devices/:id", async (req, res) => {
  const { id } = req.params;
  const { hostname, ip_address, snmp_community, options } = req.body;

  try {
    await db.query(
      "UPDATE devices SET hostname=?, ip_address=?, snmp_community=?, options=? WHERE id=?",
      [hostname, ip_address, snmp_community, options, id]
    );
    res.json({ message: "Device updated successfully" });
  } catch (err) {
    console.error("Update error:", err.message);
    res.status(500).json({ error: "Failed to update device" });
  }
});

/* ================= DELETE DEVICE ================= */
app.delete("/api/devices/:id", async (req, res) => {
  const { id } = req.params;
  try {
    // Note: Due to ON DELETE CASCADE in your SQL, 
    // this will automatically delete associated interfaces.
    await db.query("DELETE FROM devices WHERE id = ?", [id]);
    res.json({ message: "Device deleted successfully" });
  } catch (err) {
    console.error("Delete error:", err.message);
    res.status(500).json({ error: "Failed to delete device" });
  }
});


app.get('/api/ping', async (req, res) => {
  const { host } = req.query;

  // Validation: If host is missing or literally the string "undefined"
  if (!host || host === 'undefined') {
    return res.status(400).json({ error: "Host parameter is required" });
  }

  try {
    const lookup = await dns.lookup(host);
    const ip = lookup.address;

    const result = await ping.promise.probe(ip, { timeout: 2 });

    res.json({
      host: host,
      ip: ip,
      latency: result.alive ? Math.round(result.time) : "Timeout",
      status: result.alive ? "online" : "offline"
    });
  } catch (error) {
    console.error(`Error pinging ${host}:`, error.message);
    res.status(500).json({ error: "Failed to resolve or ping host", details: error.message });
  }
});


/* ================= API ROUTES ================= */

// Add these routes for interfacesnotinuse
app.get('/api/interfacesnotinuse', async (req, res) => {
  const query = `
    SELECT i.*, d.hostname AS device_name
    FROM interfacesnotinuse i
    LEFT JOIN devices d ON i.device_id = d.id
  `;
  try {
    const [results] = await db.query(query);
    console.log('Fetched interfacesnotinuse results:', results); // Debug log
    res.json(results);
  } catch (err) {
    console.error('Error fetching interfacesnotinuse:', err);
    res.status(500).json({ error: 'Failed to fetch', details: err.message });
  }
});

// POST /api/interfacesnotinuse - Insert an interface into not-in-use table
app.post('/api/interfacesnotinuse', (req, res) => {
  const { device_id, ifIndex, ifDescr, ifName, ifAlias, ifOperStatus } = req.body;
  const query = `INSERT INTO interfacesnotinuse (device_id, ifIndex, ifDescr, ifName, ifAlias, ifOperStatus) VALUES (?, ?, ?, ?, ?, ?)`;
  db.query(query, [device_id, ifIndex, ifDescr, ifName, ifAlias, ifOperStatus], (err, result) => {
    if (err) {
      console.error('Error inserting into interfacesnotinuse:', err);
      return res.status(500).json({ error: 'Failed to insert' });
    }
    res.status(201).json({ message: 'Inserted successfully', id: result.insertId });
  });
});

// DELETE /api/interfacesnotinuse/:id - Delete by id
app.delete('/api/interfacesnotinuse/:id', (req, res) => {
  const { id } = req.params;
  const query = `DELETE FROM interfacesnotinuse WHERE id = ?`;
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error deleting from interfacesnotinuse:', err);
      return res.status(500).json({ error: 'Failed to delete' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Not found' });
    }
    res.json({ message: 'Deleted successfully' });
  });
});

// ... (rest of your app code)

// GET /api/pingtable - Fetch all data, grouped by category
app.get('/api/pingtable', async (req, res) => {
  try {
    const query = 'SELECT * FROM pingtable';
    const [results] = await db.query(query); // Use await for promise-based query

    // Group by category
    const tabData = {};
    const latencyGroups = {};
    results.forEach(row => {
      if (!tabData[row.category]) tabData[row.category] = [];
      tabData[row.category].push(row.name);

      latencyGroups[row.name] = {
        best: [row.best_low, row.best_high],
        someHigh: [row.somehigh_low, row.somehigh_high],
        veryHigh: [row.veryhigh_low, row.veryhigh_high]
      };
    });

    res.json({ tabData, latencyGroups });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/pingtable - Add new entry
app.post('/api/pingtable', async (req, res) => {
  try {
    const { name, best_low, best_high, somehigh_low, somehigh_high, veryhigh_low, veryhigh_high, category } = req.body;
    const query = 'INSERT INTO pingtable (name, best_low, best_high, somehigh_low, somehigh_high, veryhigh_low, veryhigh_high, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    await db.query(query, [name, best_low, best_high, somehigh_low, somehigh_high, veryhigh_low, veryhigh_high, category]); // Use await
    res.json({ message: 'Added successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/pingtable/:name - Update an entry
app.put('/api/pingtable/:name', async (req, res) => {
  try {
    const { name } = req.params;
    const { best_low, best_high, somehigh_low, somehigh_high, veryhigh_low, veryhigh_high, category } = req.body;
    const query = 'UPDATE pingtable SET best_low=?, best_high=?, somehigh_low=?, somehigh_high=?, veryhigh_low=?, veryhigh_high=?, category=? WHERE name=?';
    await db.query(query, [best_low, best_high, somehigh_low, somehigh_high, veryhigh_low, veryhigh_high, category, name]);
    res.json({ message: 'Updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/pingtable/:name - Delete an entry
app.delete('/api/pingtable/:name', async (req, res) => {
  try {
    const { name } = req.params;
    const query = 'DELETE FROM pingtable WHERE name=?';
    await db.query(query, [name]);
    res.json({ message: 'Deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ping?host=name - Ping and get latency/IP
app.get('/api/ping', async (req, res) => {
  const host = req.query.host;
  try {
    const pingRes = await ping.promise.probe(host);
    const latency = pingRes.time !== 'unknown' ? parseFloat(pingRes.time) : null;

    dns.lookup(host, (err, address) => {
      const ip = err ? 'N/A' : address;
      res.json({ latency, ip });
    });
  } catch (err) {
    res.status(500).json({ error: 'Ping failed' });
  }
});



/* ================= START ================= */
const port = process.env.PORT || 5000;
server.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
});
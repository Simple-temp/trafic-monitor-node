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
const { sendAlert } = require("./telegramManager");

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
  bgpPeerFsmEstablishedTime: "1.3.6.1.2.1.15.3.1.16",
  bgpPeerState: "1.3.6.1.2.1.15.3.1.2",
  bgpPeerRemoteAddr: "1.3.6.1.2.1.15.3.1.7",
  bgpPeerRemoteAs: "1.3.6.1.2.1.15.3.1.9",
  ipAdEntAddr: "1.3.6.1.2.1.4.20.1.1",  // IP address
  ipAdEntIfIndex: "1.3.6.1.2.1.4.20.1.2"  // Corresponding ifIndex
};

/* ================= ALLOWED PREFIXES ================= */
const allowedPrefixes = [
  "ae", "et", "lt", "xe", "10GE", "20GE", "30GE", "40GE", "25GE",
  "100GE", "Ethernet", "GigaEthernet", "TGigaEthernet",
];

/* ================= STATE ================= */
const lastCounters = {};
const liveTraffic = {};
const previousStatuses = {};  // Track previous port statuses for change detection
const previousDeviceStatuses = {};  // New: Track previous device statuses for change detection

/* ================= HELPER FUNCTION ================= */
function startsWithAllowedPrefix(str, prefixes) {
  if (!str) return false;
  return prefixes.some(prefix => str.startsWith(prefix));
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
    const pingRes = await ping.promise.probe(device.ip_address, { timeout: 15 });

    const currentDeviceStatus = pingRes.alive ? "UP" : "DOWN";

    await db.query("UPDATE devices SET status=? WHERE id=?", [
      currentDeviceStatus,
      device.id,
    ]);

    if (!pingRes.alive) {
      // Device unreachable: Set all stored ports to DOWN (2)
      const [interfaces] = await db.query("SELECT ifIndex FROM interfaces WHERE device_id = ?", [device.id]);
      interfaces.forEach(iface => {
        if (!liveTraffic[device.id]) liveTraffic[device.id] = {};
        liveTraffic[device.id][iface.ifIndex] = { status: 2 }; // DOWN
        // New: Update previous port statuses to DOWN
        if (!previousStatuses[device.id]) previousStatuses[device.id] = {};
        previousStatuses[device.id][iface.ifIndex] = 2;
      });
      // Alert already sent above for device DOWN
      console.log(`Device ${device.ip_address} unreachable: All stored ports set to DOWN`);
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

    // Poll interface data (added ifAlias)
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

    // Filter interfaces based on allowedPrefixes for ifDescr or ifName
    const filteredMap = {};
    for (const ifIndex in map) {
      const i = map[ifIndex];
      if (startsWithAllowedPrefix(i.ifDescr?.toString(), allowedPrefixes) || startsWithAllowedPrefix(i.ifName?.toString(), allowedPrefixes)) {
        filteredMap[ifIndex] = i;
      }
    }

    // Insert/update only filtered interfaces
    for (const ifIndex in filteredMap) {
      const i = filteredMap[ifIndex];

      await db.query(
        `INSERT INTO interfaces
        (device_id, ifIndex, ifDescr, ifName, ifAlias, ifType, ifSpeed, ifAdminStatus, ifOperStatus, ifInErrors, ifOutErrors, ifInDiscards, ifOutDiscards, last_polled)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())
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
        ]
      );

      if (!lastCounters[device.id][ifIndex]) {
        lastCounters[device.id][ifIndex] = { in: 0, out: 0, t: now };
        liveTraffic[device.id][ifIndex] = { rx: 0, tx: 0 };
      }
    }

    // Poll traffic counters (only for filtered interfaces)
    const ins = await snmpWalk(session, OIDS.ifIn);
    const outs = await snmpWalk(session, OIDS.ifOut);

    ins.forEach((v) => {
      const idx = Number(v.oid.split(".").pop());
      if (!filteredMap[idx]) return; // Skip if not in filtered map
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
      if (!filteredMap[idx]) return; // Skip if not in filtered map
      const prev = lastCounters[device.id][idx];
      if (!prev) return;

      const dt = (now - prev.t) / 1000 || 1;
      liveTraffic[device.id][idx].tx =
        Math.max(((Number(v.value) - prev.out) * 8) / dt, 0);

      prev.out = Number(v.value);
      prev.t = now;
    });

    // Poll ifOperStatus for status (only for filtered interfaces)
    const operStatuses = await snmpWalk(session, OIDS.ifOper);

    // After: Telegram SETUP

    // 1. Identify interfaces (Added ifName and ifAlias for better accuracy)
    const [namess, aliasess, operss] = await Promise.all([
      snmpWalk(session, OIDS.ifName),   // e.g., "ae1" or "xe-0/0/1"
      snmpWalk(session, OIDS.ifAlias),  // The actual description field (Alias)
      snmpWalk(session, OIDS.ifOper),   // Link status
    ]);

    const ifMap = {};

    // Map the Technical Names (ifName)
    namess.forEach(v => {
      const idx = Number(v.oid.split(".").pop());
      ifMap[idx] = { ...ifMap[idx], name: v.value.toString() };
    });

    // Map the User-defined Descriptions (ifAlias)
    aliasess.forEach(v => {
      const idx = Number(v.oid.split(".").pop());
      ifMap[idx] = { ...ifMap[idx], alias: v.value.toString() };
    });

    // 2. Process statuses and send alerts
    operss.forEach((v) => {
      const idx = Number(v.oid.split(".").pop());
      const status = Number(v.value); // 1 = UP, 2 = DOWN

      // portName: Used for filtering logic in telegrammanager.js
      const portName = ifMap[idx]?.name || `Port-${idx}`;

      // portDescription: The human-readable Alias
      const portDescription = ifMap[idx]?.alias && ifMap[idx].alias.trim() !== ""
        ? ifMap[idx].alias
        : "No Description";

      if (!liveTraffic[device.id]) liveTraffic[device.id] = {};
      if (!liveTraffic[device.id][idx]) liveTraffic[device.id][idx] = {};

      // Check for status change
      const prevStatus = previousStatuses[device.id]?.[idx];

      if (prevStatus !== undefined && prevStatus !== status) {
        const statusEmoji = status === 1 ? "🟢 UP" : "🔴 DOWN";
        const alertMsg = `*Port Alert*\n` +
          `*Device:* ${device.hostname || 'Unknown'}\n` +
          `*Interface:* ${portName}\n` +
          `*Description:* ${portDescription}\n` +
          `*Status:* ${statusEmoji}\n`;

        // Send to manager: portName is used for Regex check
        sendAlert(device.ip_address, alertMsg, portName);
      }

      // Update state
      if (!previousStatuses[device.id]) previousStatuses[device.id] = {};
      previousStatuses[device.id][idx] = status;
      liveTraffic[device.id][idx].status = status;
    });

    // Telegram SETUP END


// Poll IP addresses to map IPs to ifIndex (for BGP local addr association)
const ipAddrs = await snmpWalk(session, OIDS.ipAdEntAddr);
const ipIfIndices = await snmpWalk(session, OIDS.ipAdEntIfIndex);
const ipToIfIndex = {};
ipAddrs.forEach((v, i) => {
  const ip = v.value.toString();
  const ifIndex = Number(ipIfIndices[i]?.value) || 0;
  ipToIfIndex[ip] = ifIndex;
  console.log(`IP Mapping: ${ip} -> ifIndex ${ifIndex}`);  // Debug log
});

// Log ifMap for debugging
console.log('ifMap keys:', Object.keys(ifMap));  // Check if interfaces are loaded

// Poll BGP peers separately
try {
  const [
    bgpStates,
    bgpAddrs,
    bgpAsns,
    bgpTimes,
    bgpLocalAddrs
  ] = await Promise.all([
    snmpWalk(session, OIDS.bgpPeerState),
    snmpWalk(session, OIDS.bgpPeerRemoteAddr),
    snmpWalk(session, OIDS.bgpPeerRemoteAs),
    snmpWalk(session, OIDS.bgpPeerFsmEstablishedTime),
    snmpWalk(session, OIDS.bgpPeerLocalAddr)
  ]);

  if (bgpStates.length > 0) {
    console.log(`Found ${bgpStates.length} BGP peers for ${device.ip_address}`);
    const bgpMap = {};
    const bgpAdd = (arr, key) =>
      arr.forEach((v) => {
        const idx = Number(v.oid.split(".").pop());
        bgpMap[idx] = bgpMap[idx] || {};
        bgpMap[idx][key] = v.value;
      });

    bgpAdd(bgpStates, "bgpPeerState");
    bgpAdd(bgpAddrs, "bgpPeerRemoteAddr");
    bgpAdd(bgpAsns, "bgpPeerRemoteAs");
    bgpAdd(bgpTimes, "bgpPeerFsmEstablishedTime");
    bgpAdd(bgpLocalAddrs, "bgpPeerLocalAddr");

    // Insert/update BGP peers (assuming 'bgp_peers' table exists with new columns)
    for (const peerIndex in bgpMap) {
      const peer = bgpMap[peerIndex];
      const localAddr = peer.bgpPeerLocalAddr?.toString() || "";
      const ifIndex = ipToIfIndex[localAddr] || 0;
      const interfaceName = ifMap[ifIndex]?.name?.toString() || "";
      const interfaceAlias = ifMap[ifIndex]?.alias?.toString() || "";

      console.log(`BGP Peer ${peerIndex}: localAddr=${localAddr}, ifIndex=${ifIndex}, interfaceName=${interfaceName}, interfaceAlias=${interfaceAlias}`);  // Debug log

      // If mapping fails, try alternative: assume peerIndex == ifIndex (unreliable, but common on some devices)
      let altInterfaceName = interfaceName;
      let altInterfaceAlias = interfaceAlias;
      if (!interfaceName && ifMap[peerIndex]) {
        altInterfaceName = ifMap[peerIndex]?.name?.toString() || "";
        altInterfaceAlias = ifMap[peerIndex]?.alias?.toString() || "";
        console.log(`Using alternative mapping for Peer ${peerIndex}: interfaceName=${altInterfaceName}, interfaceAlias=${altInterfaceAlias}`);
      }

      await db.query(
        `INSERT INTO bgp_peers
        (device_id, peer_index, bgpPeerState, bgpPeerRemoteAddr, bgpPeerRemoteAs, bgpPeerFsmEstablishedTime, interface_name, interface_alias, last_polled)
        VALUES (?,?,?,?,?,?,?,?,NOW())
        ON DUPLICATE KEY UPDATE
        bgpPeerState=VALUES(bgpPeerState),
        bgpPeerRemoteAddr=VALUES(bgpPeerRemoteAddr),
        bgpPeerRemoteAs=VALUES(bgpPeerRemoteAs),
        bgpPeerFsmEstablishedTime=VALUES(bgpPeerFsmEstablishedTime),
        interface_name=VALUES(interface_name),
        interface_alias=VALUES(interface_alias),
        last_polled=NOW()`,
        [
          device.id,
          peerIndex,
          peer.bgpPeerState || 0,
          peer.bgpPeerRemoteAddr?.toString() || "",
          peer.bgpPeerRemoteAs || 0,
          peer.bgpPeerFsmEstablishedTime || 0,
          altInterfaceName || interfaceName,  // Use alternative if primary fails
          altInterfaceAlias || interfaceAlias
        ]
      );
    }
  } else {
    console.log(`No BGP peers found for ${device.ip_address}`);
  }
} catch (bgpErr) {
  console.warn(`BGP polling failed for ${device.ip_address}: ${bgpErr.message}`);
}


    session.close();
  } catch (err) {
    console.error(`Poll failed for ${device.ip_address}:`, err.message);
    // On error, assume DOWN (2) for stored interfaces
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
setInterval(async () => {
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
}, 90000);

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

    const result = await ping.promise.probe(ip, { timeout: 1 });

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
      tabData[row.category].push({ id: row.id, name: row.name });

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

// PUT /api/pingtable/:id - Update an entry
app.put('/api/pingtable/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, best_low, best_high, somehigh_low, somehigh_high, veryhigh_low, veryhigh_high, category } = req.body;
    const query = 'UPDATE pingtable SET name=?, best_low=?, best_high=?, somehigh_low=?, somehigh_high=?, veryhigh_low=?, veryhigh_high=?, category=? WHERE id=?';
    await db.query(query, [name, best_low, best_high, somehigh_low, somehigh_high, veryhigh_low, veryhigh_high, category, id]);
    res.json({ message: 'Updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/pingtable/:id - Delete an entry
app.delete('/api/pingtable/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const query = 'DELETE FROM pingtable WHERE id=?';
    await db.query(query, [id]);
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
    // If time is unknown, we explicitly send "Timeout"
    const latency = pingRes.time !== 'unknown' ? parseFloat(pingRes.time) : "Timeout";

    dns.lookup(host, (err, address) => {
      const ip = err ? 'N/A' : address;
      // ALWAYS return the host so the frontend can match it
      res.json({ host, latency, ip });
    });
  } catch (err) {
    // Send 200 even on error, but mark as Timeout, so frontend doesn't trigger global 'catch'
    res.json({ host, latency: "Timeout", ip: "N/A" });
  }
});

app.get('/api/bgppeers', async (req, res) => {
  try {
    const { device_id } = req.query;  // Optional query param: ?device_id=123

    let query = `
      SELECT bp.id, bp.device_id, bp.peer_index, bp.bgpPeerState, bp.bgpPeerRemoteAddr, bp.bgpPeerRemoteAs, bp.bgpPeerFsmEstablishedTime, bp.interface_name, bp.interface_alias, bp.last_polled,
             d.ip_address, d.hostname
      FROM bgp_peers bp
      JOIN devices d ON bp.device_id = d.id
    `;
    const params = [];

    if (device_id) {
      query += ' WHERE bp.device_id = ?';
      params.push(device_id);
    }

    query += ' ORDER BY bp.device_id, bp.peer_index';

    const [rows] = await db.query(query, params);

    // Map BGP states to human-readable strings (optional, for better UX)
    const stateMap = {
      1: 'idle',
      2: 'connect',
      3: 'active',
      4: 'opensent',
      5: 'openconfirm',
      6: 'established'
    };
    const formattedRows = rows.map(row => ({
      ...row,
      bgpPeerStateText: stateMap[row.bgpPeerState] || 'unknown'
    }));

    res.json({
      success: true,
      data: formattedRows,
      count: formattedRows.length
    });
  } catch (err) {
    console.error('Error fetching BGP peers:', err.message);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch BGP peers',
      details: err.message
    });
  }
});

/* ================= START ================= */
const port = process.env.PORT || 5000;
server.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
});
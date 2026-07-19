// PostgreSQL data layer for the control panel.
//
// Everything the HTTP layer needs — users, devices, real-location reports and a
// tiny key/value meta table (session secret) — lives here so server.js stays a
// thin routing layer. Rows are mapped to the same JS shape the old JSON store
// used ({ spoofed:{...}, real:{...} }) so the request handlers barely changed.
//
// Connection: set DATABASE_URL (Coolify's Postgres gives you one). Tables are
// created on first boot; an existing legacy data.json is imported once.

const { Pool } = require("pg");
const crypto = require("crypto");
const fs = require("fs");

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || "";
// Coolify's internal Postgres talks plaintext on the private network; a managed
// external DB usually wants SSL. Opt in with PGSSL=require (self-signed ok).
const wantSsl = /^(1|true|require)$/i.test(String(process.env.PGSSL || ""));

const pool = new Pool({
  connectionString: DATABASE_URL || undefined,
  ssl: wantSsl ? { rejectUnauthorized: false } : false,
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
});

pool.on("error", (err) => {
  console.error("Postgres pool error: " + err.message);
});

function q(text, params) {
  return pool.query(text, params);
}

// ---------- schema ----------
const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  username   TEXT PRIMARY KEY,
  role       TEXT NOT NULL DEFAULT 'user',
  salt       TEXT NOT NULL,
  hash       TEXT NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  owner       TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  token       TEXT NOT NULL UNIQUE,
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  report_real BOOLEAN NOT NULL DEFAULT FALSE,
  spoof_lat   DOUBLE PRECISION,
  spoof_lng   DOUBLE PRECISION,
  spoof_alt   INTEGER,
  spoof_hacc  INTEGER,
  spoof_vacc  INTEGER,
  real_lat    DOUBLE PRECISION,
  real_lng    DOUBLE PRECISION,
  real_alt    INTEGER,
  real_ts     BIGINT,
  real_acc    DOUBLE PRECISION,
  real_src    TEXT,
  real_diag   TEXT,
  last_seen   BIGINT,
  last_report BIGINT,
  created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner);

CREATE TABLE IF NOT EXISTS position_reports (
  id        BIGSERIAL PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  lat       DOUBLE PRECISION NOT NULL,
  lng       DOUBLE PRECISION NOT NULL,
  alt       INTEGER,
  acc       INTEGER,
  src       TEXT,
  ts        BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_device_ts ON position_reports(device_id, ts DESC);
`;

// Best-effort, idempotent upgrades for databases created by an earlier version.
// Failures are ignored (a fresh DB already has these columns from SCHEMA).
const MIGRATIONS = [
  "ALTER TABLE devices ADD COLUMN IF NOT EXISTS real_acc DOUBLE PRECISION",
  "ALTER TABLE devices ADD COLUMN IF NOT EXISTS real_src TEXT",
  "ALTER TABLE devices ADD COLUMN IF NOT EXISTS real_diag TEXT",
  "ALTER TABLE position_reports ADD COLUMN IF NOT EXISTS acc INTEGER",
  "ALTER TABLE position_reports ADD COLUMN IF NOT EXISTS src TEXT",
];

// ---------- helpers ----------
function safeJson(s) {
  try {
    return s ? JSON.parse(s) : null;
  } catch (e) {
    return null;
  }
}
function haversineKm(aLat, aLng, bLat, bLng) {
  const R = 6371,
    toR = Math.PI / 180;
  const dLat = (bLat - aLat) * toR,
    dLng = (bLng - aLng) * toR;
  const s =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(aLat * toR) * Math.cos(bLat * toR) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
  return 2 * R * Math.asin(Math.sqrt(s));
}
// Sanitise the diagnostics blob the device sends (reference AP points, capped).
function clampDiag(diag) {
  if (!diag || typeof diag !== "object") return null;
  const out = {
    source: diag.source === "wifi" || diag.source === "cell" ? diag.source : null,
    count: Number.isFinite(Number(diag.count)) ? Math.round(Number(diag.count)) : null,
    accuracy: Number.isFinite(Number(diag.accuracy)) ? Math.round(Number(diag.accuracy)) : null,
    points: [],
  };
  if (Array.isArray(diag.points)) {
    for (let i = 0; i < diag.points.length && out.points.length < 80; i++) {
      const p = diag.points[i];
      if (
        Array.isArray(p) &&
        p.length >= 2 &&
        isFinite(p[0]) &&
        isFinite(p[1]) &&
        Math.abs(p[0]) <= 90 &&
        Math.abs(p[1]) <= 180
      ) {
        out.points.push([Math.round(p[0] * 1e5) / 1e5, Math.round(p[1] * 1e5) / 1e5]);
      }
    }
  }
  return out;
}

// A far jump from the current displayed real is treated as a transient glitch
// (a bad Apple AP entry) and does NOT move the marker — unless the previous raw
// report was already near the new spot, i.e. a real sustained move.
const JUMP_KM = 30;

// ---------- row mapping ----------
// Map a devices row to the object shape the HTTP layer and frontend expect.
function rowToDevice(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    owner: r.owner,
    token: r.token,
    enabled: r.enabled !== false,
    reportReal: r.report_real === true,
    spoofed: {
      latitude: r.spoof_lat,
      longitude: r.spoof_lng,
      altitude: r.spoof_alt,
      horizontalAccuracy: r.spoof_hacc,
      verticalAccuracy: r.spoof_vacc,
    },
    real:
      r.real_lat != null && r.real_lng != null
        ? {
            latitude: r.real_lat,
            longitude: r.real_lng,
            altitude: r.real_alt != null ? r.real_alt : undefined,
            accuracy: r.real_acc != null ? Number(r.real_acc) : null,
            source: r.real_src || null,
            diag: safeJson(r.real_diag),
            ts: r.real_ts != null ? Number(r.real_ts) : null,
          }
        : null,
    lastSeen: r.last_seen != null ? Number(r.last_seen) : null,
    lastReport: r.last_report != null ? Number(r.last_report) : null,
    createdAt: r.created_at != null ? Number(r.created_at) : null,
  };
}

// ---------- meta ----------
async function getMeta(key) {
  const r = await q("SELECT value FROM meta WHERE key = $1", [key]);
  return r.rows[0] ? r.rows[0].value : null;
}
async function setMeta(key, value) {
  await q(
    "INSERT INTO meta(key, value) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    [key, value],
  );
}

// ---------- users ----------
async function countUsers() {
  const r = await q("SELECT COUNT(*)::int AS n FROM users");
  return r.rows[0].n;
}
async function getUser(username) {
  const r = await q("SELECT * FROM users WHERE username = $1", [username]);
  return r.rows[0] || null;
}
async function listUsers() {
  const r = await q(
    `SELECT u.username, u.role, u.created_at, COUNT(d.id)::int AS devices
       FROM users u
       LEFT JOIN devices d ON d.owner = u.username
      GROUP BY u.username, u.role, u.created_at
      ORDER BY u.created_at ASC`,
  );
  return r.rows.map((x) => ({
    username: x.username,
    role: x.role,
    devices: x.devices,
    createdAt: Number(x.created_at),
  }));
}
async function createUser({ username, role, salt, hash, createdAt }) {
  await q(
    "INSERT INTO users(username, role, salt, hash, created_at) VALUES($1,$2,$3,$4,$5)",
    [username, role, salt, hash, createdAt],
  );
}
async function setUserPassword(username, salt, hash) {
  await q("UPDATE users SET salt = $2, hash = $3 WHERE username = $1", [
    username,
    salt,
    hash,
  ]);
}
async function deleteUser(username) {
  // devices cascade via FK.
  await q("DELETE FROM users WHERE username = $1", [username]);
}

// ---------- devices ----------
async function listDevices(me, isAdmin) {
  const r = isAdmin
    ? await q("SELECT * FROM devices ORDER BY created_at ASC")
    : await q("SELECT * FROM devices WHERE owner = $1 ORDER BY created_at ASC", [
        me,
      ]);
  return r.rows.map(rowToDevice);
}
async function getDevice(id) {
  const r = await q("SELECT * FROM devices WHERE id = $1", [id]);
  return rowToDevice(r.rows[0]);
}
async function getDeviceByToken(token) {
  if (!token) return null;
  const r = await q("SELECT * FROM devices WHERE token = $1", [token]);
  return rowToDevice(r.rows[0]);
}
async function createDevice(d) {
  await q(
    `INSERT INTO devices(id, name, owner, token, enabled, report_real,
        spoof_lat, spoof_lng, spoof_alt, spoof_hacc, spoof_vacc, created_at)
     VALUES($1,$2,$3,$4,TRUE,FALSE,$5,$6,$7,$8,$9,$10)`,
    [
      d.id,
      d.name,
      d.owner,
      d.token,
      d.spoofed.latitude,
      d.spoofed.longitude,
      d.spoofed.altitude,
      d.spoofed.horizontalAccuracy,
      d.spoofed.verticalAccuracy,
      d.createdAt,
    ],
  );
  return getDevice(d.id);
}
async function updateDeviceSpoof(id, s) {
  const r = await q(
    `UPDATE devices SET spoof_lat=$2, spoof_lng=$3, spoof_alt=$4,
        spoof_hacc=$5, spoof_vacc=$6, enabled=TRUE WHERE id=$1 RETURNING *`,
    [
      id,
      s.latitude,
      s.longitude,
      s.altitude,
      s.horizontalAccuracy,
      s.verticalAccuracy,
    ],
  );
  return rowToDevice(r.rows[0]);
}
async function setDeviceEnabled(id, enabled) {
  const r = await q(
    "UPDATE devices SET enabled=$2 WHERE id=$1 RETURNING *",
    [id, !!enabled],
  );
  return rowToDevice(r.rows[0]);
}
async function renameDevice(id, name) {
  const r = await q("UPDATE devices SET name=$2 WHERE id=$1 RETURNING *", [
    id,
    name,
  ]);
  return rowToDevice(r.rows[0]);
}
async function setDeviceToken(id, token) {
  const r = await q("UPDATE devices SET token=$2 WHERE id=$1 RETURNING *", [
    id,
    token,
  ]);
  return rowToDevice(r.rows[0]);
}
// Toggle real reporting. Turning it off discards the stored real fix and history.
async function setReportReal(id, on) {
  if (on) {
    const r = await q(
      "UPDATE devices SET report_real=TRUE WHERE id=$1 RETURNING *",
      [id],
    );
    return rowToDevice(r.rows[0]);
  }
  const r = await q(
    `UPDATE devices SET report_real=FALSE, real_lat=NULL, real_lng=NULL,
        real_alt=NULL, real_ts=NULL, real_acc=NULL, real_src=NULL, real_diag=NULL,
        last_report=NULL WHERE id=$1 RETURNING *`,
    [id],
  );
  await q("DELETE FROM position_reports WHERE device_id=$1", [id]);
  return rowToDevice(r.rows[0]);
}
async function recordReal(id, la, lo, alt, ts, acc, src, diag) {
  const altInt = Number.isFinite(Number(alt)) ? Math.round(Number(alt)) : null;
  const accInt =
    Number.isFinite(Number(acc)) && Number(acc) >= 0 ? Math.round(Number(acc)) : null;
  const source = src === "wifi" || src === "cell" ? src : null;
  const clean = clampDiag(diag);
  const diagJson = clean ? JSON.stringify(clean) : null;

  // Current displayed real + the most recent raw report (before inserting this one).
  const curRow = (await q("SELECT real_lat, real_lng FROM devices WHERE id=$1", [id]))
    .rows[0];
  const prevRow = (
    await q(
      "SELECT lat, lng FROM position_reports WHERE device_id=$1 ORDER BY ts DESC LIMIT 1",
      [id],
    )
  ).rows[0];

  // Always keep the raw report for history / diagnostics.
  await q(
    "INSERT INTO position_reports(device_id, lat, lng, alt, acc, src, ts) VALUES($1,$2,$3,$4,$5,$6,$7)",
    [id, la, lo, altInt, accInt, source, ts],
  );

  // Stability filter: reject a lone far jump from the current real; accept it only
  // if the previous raw report was already near this new spot (a sustained move).
  let accept = true;
  if (curRow && curRow.real_lat != null) {
    const jump = haversineKm(la, lo, curRow.real_lat, curRow.real_lng);
    if (jump > JUMP_KM) {
      accept = !!prevRow && haversineKm(la, lo, prevRow.lat, prevRow.lng) < JUMP_KM;
    }
  }

  if (accept) {
    const r = await q(
      `UPDATE devices SET real_lat=$2, real_lng=$3, real_alt=$4, real_ts=$5,
          real_acc=$6, real_src=$7, real_diag=$8, last_report=$5, last_seen=$5
         WHERE id=$1 RETURNING *`,
      [id, la, lo, altInt, ts, accInt, source, diagJson],
    );
    return rowToDevice(r.rows[0]);
  }
  // Rejected transient jump: keep the displayed real, just mark the device alive.
  const r = await q("UPDATE devices SET last_seen=$2 WHERE id=$1 RETURNING *", [id, ts]);
  return rowToDevice(r.rows[0]);
}
async function touchLastSeen(id, ts) {
  await q("UPDATE devices SET last_seen=$2 WHERE id=$1", [id, ts]);
}
async function deleteDevice(id) {
  await q("DELETE FROM devices WHERE id=$1", [id]);
}
async function deviceHistory(id, limit) {
  const r = await q(
    "SELECT lat, lng, alt, acc, src, ts FROM position_reports WHERE device_id=$1 ORDER BY ts DESC LIMIT $2",
    [id, Math.min(Math.max(Number(limit) || 50, 1), 500)],
  );
  return r.rows.map((x) => ({
    latitude: x.lat,
    longitude: x.lng,
    altitude: x.alt != null ? x.alt : undefined,
    accuracy: x.acc != null ? Number(x.acc) : null,
    source: x.src || null,
    ts: Number(x.ts),
  }));
}

// ---------- one-time legacy import ----------
// If a pre-2.0 data.json sits next to server.js and the DB has no users yet,
// pull its users/devices in so an existing admin keeps working after migration.
async function importLegacyJson(dataFile) {
  try {
    if (!dataFile || !fs.existsSync(dataFile)) return;
    if ((await countUsers()) > 0) return;
    const legacy = JSON.parse(fs.readFileSync(dataFile, "utf8"));
    if (!legacy || !legacy.users) return;
    const users = legacy.users || {};
    for (const uname of Object.keys(users)) {
      const u = users[uname];
      if (!u || !u.salt || !u.hash) continue;
      await createUser({
        username: uname,
        role: u.role === "admin" ? "admin" : "user",
        salt: u.salt,
        hash: u.hash,
        createdAt: u.createdAt || Date.now(),
      });
    }
    const devices = legacy.devices || {};
    for (const id of Object.keys(devices)) {
      const d = devices[id];
      if (!d || !d.token || !users[d.owner]) continue;
      const s = d.spoofed || {};
      await createDevice({
        id: d.id || id,
        name: d.name || "Device",
        owner: d.owner,
        token: d.token,
        spoofed: {
          latitude: s.latitude != null ? s.latitude : null,
          longitude: s.longitude != null ? s.longitude : null,
          altitude: s.altitude != null ? s.altitude : null,
          horizontalAccuracy: s.horizontalAccuracy != null ? s.horizontalAccuracy : null,
          verticalAccuracy: s.verticalAccuracy != null ? s.verticalAccuracy : null,
        },
        createdAt: d.createdAt || Date.now(),
      });
      if (d.enabled === false) await setDeviceEnabled(id, false);
    }
    console.log(
      "Imported legacy data.json: " +
        Object.keys(users).length +
        " users, " +
        Object.keys(devices).length +
        " devices.",
    );
  } catch (e) {
    console.log("Legacy data.json import skipped: " + e.message);
  }
}

// ---------- init ----------
async function init(opts) {
  opts = opts || {};
  if (!DATABASE_URL) {
    throw new Error(
      "DATABASE_URL is not set. Point it at your Postgres, e.g. postgres://user:pass@host:5432/db",
    );
  }
  // Retry a few times: on Coolify the app can boot before Postgres is ready.
  let lastErr;
  for (let attempt = 1; attempt <= 10; attempt++) {
    try {
      await q("SELECT 1");
      lastErr = null;
      break;
    } catch (e) {
      lastErr = e;
      console.log(
        "Waiting for Postgres (" + attempt + "/10): " + e.message,
      );
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  if (lastErr) throw lastErr;

  // Apply schema one statement at a time (portable across drivers/poolers).
  for (const stmt of SCHEMA.split(";")) {
    const s = stmt.trim();
    if (s) await q(s);
  }
  // Upgrade older databases; ignore per-statement failures (already-applied).
  for (const stmt of MIGRATIONS) {
    try {
      await q(stmt);
    } catch (e) {
      /* column already exists or unsupported ADD IF NOT EXISTS — fine */
    }
  }
  if (opts.legacyDataFile) await importLegacyJson(opts.legacyDataFile);
  return true;
}

module.exports = {
  pool,
  init,
  getMeta,
  setMeta,
  countUsers,
  getUser,
  listUsers,
  createUser,
  setUserPassword,
  deleteUser,
  listDevices,
  getDevice,
  getDeviceByToken,
  createDevice,
  updateDeviceSpoof,
  setDeviceEnabled,
  renameDevice,
  setDeviceToken,
  setReportReal,
  recordReal,
  touchLastSeen,
  deleteDevice,
  deviceHistory,
};

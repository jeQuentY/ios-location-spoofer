// Location control panel — multi-user admin dashboard, single file, zero deps.
//
// Roles:
//   admin  — sees and manages every device and every user
//   user   — sees and manages only their own devices
//
// Each DEVICE has its own token. The Shadowrocket/Surge/etc. module points its
//   configUrl=  at  https://host/loc.json?token=DEVICE_TOKEN
// and the (modified) location-spoofer.js POSTs the real coordinates it read
// from Apple's response to  https://host/report?token=DEVICE_TOKEN
// so the dashboard can show real vs spoofed side by side.
//
// Environment variables:
//   ADMIN_USER      default "admin". Seed admin username (first boot only).
//   ADMIN_PASS      required on first boot to create the admin. Ignored after.
//   SESSION_SECRET  optional. Cookie-signing secret. Auto-generated + persisted
//                   into the data file if not provided.
//   PORT            default 8080
//   HOST            default 0.0.0.0
//   DATA_FILE       default ./data.json (point at a mounted volume to persist)
//   CERT, KEY       optional built-in HTTPS (leave unset behind a TLS proxy)
//
// First run:
//   ADMIN_PASS=$(openssl rand -hex 12) node server.js
//   -> log in at / as "admin" with that password, then create the other users.

const http = require("http");
const https = require("https");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || "0.0.0.0";
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data.json");
const CERT = process.env.CERT || "";
const KEY = process.env.KEY || "";
const SESSION_TTL = 30 * 24 * 3600 * 1000; // 30 days

// ---------- storage (single JSON file, atomic writes) ----------
function loadDB() {
  try {
    const db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    db.users = db.users || {};
    db.devices = db.devices || {};
    db.meta = db.meta || {};
    return db;
  } catch (e) {
    return { users: {}, devices: {}, meta: {} };
  }
}
function saveDB() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  } catch (e) {}
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(DB, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}
const DB = loadDB();

// ---------- secrets / crypto ----------
function timingEqual(a, b) {
  const ab = Buffer.from(String(a)),
    bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return { salt, hash };
}
function verifyPassword(pw, salt, hash) {
  let h;
  try {
    h = crypto.scryptSync(pw, salt, 64).toString("hex");
  } catch (e) {
    return false;
  }
  return timingEqual(h, hash);
}

let SESSION_SECRET = process.env.SESSION_SECRET || DB.meta.sessionSecret || "";
if (!SESSION_SECRET) {
  SESSION_SECRET = crypto.randomBytes(32).toString("hex");
  DB.meta.sessionSecret = SESSION_SECRET;
  saveDB();
}

// ---------- seed admin ----------
if (Object.keys(DB.users).length === 0) {
  const au = process.env.ADMIN_USER || "admin";
  const ap = process.env.ADMIN_PASS || "";
  if (!ap) {
    console.error(
      "Startup failed: no users yet and ADMIN_PASS is not set.\n" +
        "Seed the admin on first boot, e.g.:\n" +
        "  ADMIN_PASS=$(openssl rand -hex 12) node server.js",
    );
    process.exit(1);
  }
  const pw = hashPassword(ap);
  DB.users[au] = {
    role: "admin",
    salt: pw.salt,
    hash: pw.hash,
    createdAt: Date.now(),
  };
  saveDB();
  console.log('Seeded admin user "' + au + '".');
}

// ---------- sessions (signed cookie, no server state) ----------
function signSession(username) {
  const payload = Buffer.from(
    JSON.stringify({ u: username, exp: Date.now() + SESSION_TTL }),
  ).toString("base64url");
  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");
  return payload + "." + sig;
}
function readSession(cookieHeader) {
  const raw = parseCookies(cookieHeader).sid;
  if (!raw) return null;
  const i = raw.lastIndexOf(".");
  if (i < 0) return null;
  const payload = raw.slice(0, i),
    sig = raw.slice(i + 1);
  const expect = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");
  if (!timingEqual(sig, expect)) return null;
  try {
    const o = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (!o.exp || o.exp < Date.now()) return null;
    if (!DB.users[o.u]) return null;
    return o.u;
  } catch (e) {
    return null;
  }
}
function parseCookies(h) {
  const out = {};
  (h || "").split(";").forEach(function (p) {
    const i = p.indexOf("=");
    if (i > 0)
      out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

// ---------- helpers ----------
function json(res, code, obj, headers) {
  const h = Object.assign(
    { "Content-Type": "application/json", "Cache-Control": "no-store" },
    headers || {},
  );
  res.writeHead(code, h);
  res.end(JSON.stringify(obj));
}
function readBody(req, cb) {
  let b = "";
  req.on("data", function (c) {
    b += c;
    if (b.length > 1e5) req.destroy();
  });
  req.on("end", function () {
    try {
      cb(b ? JSON.parse(b) : {});
    } catch (e) {
      cb(null);
    }
  });
}
function isHttps(req) {
  return (req.headers["x-forwarded-proto"] || "").split(",")[0] === "https";
}
function setSessionCookie(req, res, val, maxAgeMs) {
  const parts = [
    "sid=" + encodeURIComponent(val),
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (maxAgeMs != null) parts.push("Max-Age=" + Math.floor(maxAgeMs / 1000));
  if (isHttps(req)) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}
function newId() {
  return crypto.randomBytes(6).toString("hex");
}
function newToken() {
  return crypto.randomBytes(24).toString("hex");
}

// Same shape the location-spoofer script expects from /loc.json.
function spooferView(d) {
  const s = d.spoofed || {};
  return {
    enabled: d.enabled !== false,
    latitude: s.latitude,
    longitude: s.longitude,
    altitude: s.altitude,
    horizontalAccuracy: s.horizontalAccuracy,
    verticalAccuracy: s.verticalAccuracy,
    // Tells the on-device script whether to POST its real coordinates back.
    // This is the ONLY switch for real-location reporting, so the dashboard's
    // "reporting real location" indicator can never be out of sync with it.
    reportReal: d.reportReal === true,
  };
}
// What the dashboard sees (device token not included unless owner/admin asks).
function deviceView(d) {
  return {
    id: d.id,
    name: d.name,
    owner: d.owner,
    enabled: d.enabled !== false,
    reportReal: d.reportReal === true,
    spoofed: d.spoofed,
    real: d.real || null,
    lastSeen: d.lastSeen || null,
    lastReport: d.lastReport || null,
    createdAt: d.createdAt,
  };
}
function findDeviceByToken(tok) {
  if (!tok) return null;
  const ids = Object.keys(DB.devices);
  for (let i = 0; i < ids.length; i++) {
    const d = DB.devices[ids[i]];
    if (d.token && timingEqual(tok, d.token)) return d;
  }
  return null;
}

const DEFAULT_SPOOF = {
  latitude: 37.3349,
  longitude: -122.00902,
  altitude: 530,
  horizontalAccuracy: 39,
  verticalAccuracy: 1000,
};

// The full proxy module the dashboard hands out for "Copy module". It is sourced
// from the real ios-location-spoofer.sgmodule so editing that file changes what
// users copy (single source of truth). We convert its argument line into a
// template: the per-device coordinates become __PLACEHOLDERS__ and a &configUrl=
// pointing at this panel is appended. The browser fills them in per device.
//
// Embedded fallback below keeps the feature working where the file is not shipped
// next to server.js (e.g. the minimal Docker image). Keep it in sync with the file.
const EMBEDDED_MODULE = [
  "#!name=iOS Location Spoofer",
  "#!desc=拦截 Apple 定位服务器回应的 GPS 坐标，替换成自定义位置。适用于 Shadowrocket。",
  "#!homepage=https://github.com/mekos2772/ios-location-spoofer",
  "",
  "[Script]",
  "iOS Location Spoofer = type=http-response,pattern=^https?:\\/\\/(?:gs-loc(?:-cn)?\\.apple\\.com|bluedot\\.is\\.autonavi\\.com(?:\\.gds\\.alibabadns\\.com)?)\\/clls\\/wloc(?:\\?.*)?$,requires-body=1,binary-body-mode=1,max-size=1048576,timeout=10,script-path=https://raw.githubusercontent.com/mekos2772/ios-location-spoofer/main/location-spoofer.js,argument=mode=response&latitude=37.3349&longitude=-122.00902&horizontalAccuracy=39&verticalAccuracy=1000&altitude=530&debug=false",
  "",
  "[MITM]",
  "hostname = %APPEND% gs-loc.apple.com, gs-loc-cn.apple.com, bluedot.is.autonavi.com, bluedot.is.autonavi.com.gds.alibabadns.com",
].join("\n");

function moduleTextToTemplate(text) {
  // Swap the per-device coordinate values for placeholders...
  let t = String(text)
    .replace(/([?&]latitude=)[^&\r\n]*/, "$1__LAT__")
    .replace(/([?&]longitude=)[^&\r\n]*/, "$1__LNG__")
    .replace(/([?&]horizontalAccuracy=)[^&\r\n]*/, "$1__HACC__")
    .replace(/([?&]verticalAccuracy=)[^&\r\n]*/, "$1__VACC__")
    .replace(/([?&]altitude=)[^&\r\n]*/, "$1__ALT__");
  // ...and append the panel's configUrl to the argument (last field on that line).
  const lines = t.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].indexOf("argument=") >= 0 && lines[i].indexOf("configUrl=") < 0) {
      lines[i] = lines[i].replace(/\s+$/, "") + "&configUrl=__CFGURL__";
    }
  }
  return lines.join("\n");
}

function loadModuleTemplate() {
  const candidates = [
    process.env.MODULE_FILE,
    path.join(__dirname, "ios-location-spoofer.sgmodule"),
    path.join(__dirname, "..", "ios-location-spoofer.sgmodule"),
  ].filter(Boolean);
  for (let i = 0; i < candidates.length; i++) {
    try {
      const txt = fs.readFileSync(candidates[i], "utf8");
      if (txt && txt.indexOf("argument=") >= 0) {
        console.log("Copy-module source: " + candidates[i]);
        return moduleTextToTemplate(txt);
      }
    } catch (e) {
      // try next candidate
    }
  }
  console.log("Copy-module source: embedded fallback (sgmodule file not found)");
  return moduleTextToTemplate(EMBEDDED_MODULE);
}
const MODULE_TEMPLATE = loadModuleTemplate();

// Render the full importable module for one device: its saved coords as the seed
// argument values, and this panel's /loc.json?token= as the live configUrl.
function fillModule(d, origin) {
  const s = d.spoofed || {};
  const num = (v, dflt) =>
    v != null && v !== "" && isFinite(Number(v)) ? Number(v) : dflt;
  return MODULE_TEMPLATE.replace("__LAT__", num(s.latitude, DEFAULT_SPOOF.latitude))
    .replace("__LNG__", num(s.longitude, DEFAULT_SPOOF.longitude))
    .replace("__HACC__", num(s.horizontalAccuracy, DEFAULT_SPOOF.horizontalAccuracy))
    .replace("__VACC__", num(s.verticalAccuracy, DEFAULT_SPOOF.verticalAccuracy))
    .replace("__ALT__", num(s.altitude, DEFAULT_SPOOF.altitude))
    .replace("__CFGURL__", origin + "/loc.json?token=" + d.token);
}
function requestOrigin(req) {
  const proto = isHttps(req) ? "https" : "http";
  return proto + "://" + (req.headers.host || "localhost");
}

// ---------- request handler ----------
function handler(req, res) {
  const url = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  const p = url.pathname,
    m = req.method;

  if (p === "/healthz" && m === "GET") return json(res, 200, { status: "ok" });
  if (p === "/favicon.ico") {
    res.writeHead(204);
    return res.end();
  }

  // ===== device-facing (device token) =====
  if (p === "/loc.json" && m === "GET") {
    if (!url.searchParams.get("token"))
      return json(res, 401, { error: "missing token" });
    const d = findDeviceByToken(url.searchParams.get("token"));
    if (!d) return json(res, 403, { error: "bad token" });
    d.lastSeen = Date.now();
    saveDB();
    return json(res, 200, spooferView(d));
  }
  if (p === "/report" && m === "POST") {
    const d = findDeviceByToken(url.searchParams.get("token"));
    if (!d) return json(res, 403, { error: "bad token" });
    // Real-location collection is opt-in per device. If the owner/admin hasn't
    // enabled it, drop the report — nothing is stored. This keeps collection and
    // the dashboard's visible indicator bound to the same single flag.
    if (d.reportReal !== true)
      return json(res, 200, { ok: true, ignored: true });
    return readBody(req, function (j) {
      if (!j) return json(res, 400, { error: "bad json" });
      const la = Number(j.lat),
        lo = Number(j.lng);
      if (
        !isFinite(la) ||
        !isFinite(lo) ||
        la < -90 ||
        la > 90 ||
        lo < -180 ||
        lo > 180
      )
        return json(res, 400, { error: "bad coords" });
      d.real = { latitude: la, longitude: lo, ts: Date.now() };
      if (isFinite(Number(j.altitude))) d.real.altitude = Number(j.altitude);
      d.lastReport = Date.now();
      d.lastSeen = Date.now();
      saveDB();
      return json(res, 200, { ok: true });
    });
  }
  // Plain "raw"-style URL that returns the full module text with this device's
  // configUrl already baked in. Paste it into Shadowrocket › Config › Modules ›
  // add from URL. Token-authed like /loc.json; served inline like a raw file.
  if (p === "/module.sgmodule" && m === "GET") {
    if (!url.searchParams.get("token"))
      return json(res, 401, { error: "missing token" });
    const d = findDeviceByToken(url.searchParams.get("token"));
    if (!d) return json(res, 403, { error: "bad token" });
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    });
    return res.end(fillModule(d, requestOrigin(req)));
  }

  // ===== auth =====
  if (p === "/api/login" && m === "POST") {
    return readBody(req, function (j) {
      if (!j || !j.username || !j.password)
        return json(res, 400, { error: "missing credentials" });
      const u = DB.users[j.username];
      if (!u || !verifyPassword(j.password, u.salt, u.hash))
        return json(res, 401, { error: "invalid login" });
      setSessionCookie(req, res, signSession(j.username), SESSION_TTL);
      return json(res, 200, { username: j.username, role: u.role });
    });
  }
  if (p === "/api/logout" && m === "POST") {
    setSessionCookie(req, res, "", 0);
    return json(res, 200, { ok: true });
  }

  // Everything below requires a session.
  const me = readSession(req.headers.cookie);
  const meUser = me ? DB.users[me] : null;
  const isAdmin = meUser && meUser.role === "admin";

  if (p.indexOf("/api/") === 0) {
    if (!me) return json(res, 401, { error: "not logged in" });

    if (p === "/api/me" && m === "GET")
      return json(res, 200, { username: me, role: meUser.role });

    // ----- devices -----
    if (p === "/api/devices" && m === "GET") {
      const list = Object.keys(DB.devices)
        .map(function (id) {
          return DB.devices[id];
        })
        .filter(function (d) {
          return isAdmin || d.owner === me;
        })
        .map(deviceView);
      return json(res, 200, { devices: list, role: meUser.role, username: me });
    }
    if (p === "/api/devices" && m === "POST") {
      return readBody(req, function (j) {
        if (!j) return json(res, 400, { error: "bad json" });
        let owner = me;
        if (isAdmin && j.owner) {
          if (!DB.users[j.owner])
            return json(res, 400, { error: "no such owner" });
          owner = j.owner;
        }
        const id = newId();
        DB.devices[id] = {
          id: id,
          name: (j.name || "Device").slice(0, 60),
          owner: owner,
          token: newToken(),
          enabled: true,
          reportReal: false,
          spoofed: Object.assign({}, DEFAULT_SPOOF),
          real: null,
          lastSeen: null,
          lastReport: null,
          createdAt: Date.now(),
        };
        saveDB();
        return json(res, 200, {
          device: deviceView(DB.devices[id]),
          token: DB.devices[id].token,
        });
      });
    }

    const dm = p.match(/^\/api\/devices\/([a-f0-9]+)(\/[a-z]+)?$/);
    if (dm) {
      const d = DB.devices[dm[1]];
      if (!d) return json(res, 404, { error: "no such device" });
      if (!isAdmin && d.owner !== me)
        return json(res, 403, { error: "not yours" });
      const sub = dm[2] || "";

      if (sub === "" && m === "GET")
        return json(res, 200, { device: deviceView(d), token: d.token });
      if (sub === "" && m === "DELETE") {
        delete DB.devices[dm[1]];
        saveDB();
        return json(res, 200, { ok: true });
      }

      if (sub === "/spoof" && m === "POST")
        return readBody(req, function (j) {
          if (!j) return json(res, 400, { error: "bad json" });
          const la = Number(j.lat),
            lo = Number(j.lng);
          if (
            !isFinite(la) ||
            !isFinite(lo) ||
            la < -90 ||
            la > 90 ||
            lo < -180 ||
            lo > 180
          )
            return json(res, 400, { error: "bad coords" });
          d.spoofed = d.spoofed || {};
          d.spoofed.latitude = la;
          d.spoofed.longitude = lo;
          ["altitude", "horizontalAccuracy", "verticalAccuracy"].forEach(
            function (k) {
              if (
                j[k] !== undefined &&
                j[k] !== null &&
                j[k] !== "" &&
                isFinite(Number(j[k]))
              )
                d.spoofed[k] = Math.round(Number(j[k]));
            },
          );
          d.enabled = true;
          saveDB();
          return json(res, 200, { device: deviceView(d) });
        });
      if (sub === "/enable" && m === "POST")
        return readBody(req, function (j) {
          d.enabled = !(j && j.enabled === false);
          saveDB();
          return json(res, 200, { device: deviceView(d) });
        });
      if (sub === "/rename" && m === "POST")
        return readBody(req, function (j) {
          if (j && j.name) {
            d.name = String(j.name).slice(0, 60);
            saveDB();
          }
          return json(res, 200, { device: deviceView(d) });
        });
      if (sub === "/token" && m === "POST") {
        d.token = newToken();
        saveDB();
        return json(res, 200, { token: d.token });
      }
      // Owner or admin toggles whether this device reports its real location.
      // Turning it off also discards any real location already collected.
      if (sub === "/reportreal" && m === "POST")
        return readBody(req, function (j) {
          d.reportReal = !!(j && j.enabled === true);
          if (!d.reportReal) {
            d.real = null;
            d.lastReport = null;
          }
          saveDB();
          return json(res, 200, { device: deviceView(d) });
        });
      return json(res, 404, { error: "not found" });
    }

    // ----- users (admin only) -----
    if (p === "/api/users") {
      if (!isAdmin) return json(res, 403, { error: "admin only" });
      if (m === "GET") {
        const list = Object.keys(DB.users).map(function (u) {
          const dev = Object.keys(DB.devices).filter(function (id) {
            return DB.devices[id].owner === u;
          }).length;
          return {
            username: u,
            role: DB.users[u].role,
            devices: dev,
            createdAt: DB.users[u].createdAt,
          };
        });
        return json(res, 200, { users: list });
      }
      if (m === "POST")
        return readBody(req, function (j) {
          if (!j || !j.username || !j.password)
            return json(res, 400, { error: "missing fields" });
          if (DB.users[j.username])
            return json(res, 400, { error: "user exists" });
          const pw = hashPassword(j.password);
          DB.users[j.username] = {
            role: j.role === "admin" ? "admin" : "user",
            salt: pw.salt,
            hash: pw.hash,
            createdAt: Date.now(),
          };
          saveDB();
          return json(res, 200, { ok: true });
        });
    }
    const um = p.match(/^\/api\/users\/([^\/]+)(\/password)?$/);
    if (um) {
      if (!isAdmin) return json(res, 403, { error: "admin only" });
      const uname = decodeURIComponent(um[1]);
      if (!DB.users[uname]) return json(res, 404, { error: "no such user" });
      if (um[2] === "/password" && m === "POST")
        return readBody(req, function (j) {
          if (!j || !j.password)
            return json(res, 400, { error: "missing password" });
          const pw = hashPassword(j.password);
          DB.users[uname].salt = pw.salt;
          DB.users[uname].hash = pw.hash;
          saveDB();
          return json(res, 200, { ok: true });
        });
      if (m === "DELETE") {
        if (uname === me)
          return json(res, 400, { error: "cannot delete yourself" });
        Object.keys(DB.devices).forEach(function (id) {
          if (DB.devices[id].owner === uname) delete DB.devices[id];
        });
        delete DB.users[uname];
        saveDB();
        return json(res, 200, { ok: true });
      }
    }

    return json(res, 404, { error: "not found" });
  }

  if (p === "/" && m === "GET") return sendHtml(res, PAGE);
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
}

function sendHtml(res, body) {
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

// ---------- start ----------
function onListenError(err) {
  if (err.code === "EADDRINUSE")
    console.error("Startup failed: port " + PORT + " is in use.");
  else if (err.code === "EACCES")
    console.error("Startup failed: no permission for port " + PORT + ".");
  else console.error("Startup failed: " + err.message);
  process.exit(1);
}
function start() {
  if (CERT && KEY) {
    try {
      const server = https.createServer(
        { cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) },
        handler,
      );
      server.on("error", onListenError);
      setInterval(
        function () {
          try {
            server.setSecureContext({
              cert: fs.readFileSync(CERT),
              key: fs.readFileSync(KEY),
            });
          } catch (e) {
            console.log("cert reload failed: " + e.message);
          }
        },
        12 * 3600 * 1000,
      );
      return server.listen(PORT, HOST, function () {
        console.log("control panel (https) on " + HOST + ":" + PORT);
      });
    } catch (e) {
      console.log("HTTPS start failed, falling back to HTTP: " + e.message);
    }
  }
  const server = http.createServer(handler);
  server.on("error", onListenError);
  server.listen(PORT, HOST, function () {
    console.log("control panel (http) on " + HOST + ":" + PORT);
  });
}
start();

// ============================ FRONTEND ============================
const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>Location Control Panel</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%233ddc84' d='M12 2C8.1 2 5 5.1 5 9c0 5.2 7 13 7 13s7-7.8 7-13c0-3.9-3.1-7-7-7zm0 9.5A2.5 2.5 0 1 1 12 6.5a2.5 2.5 0 0 1 0 5z'/%3E%3C/svg%3E">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
  :root{
    --bg:#0d1014; --surface:#151a21; --surface-2:#1b222b; --border:#28303b;
    --text:#e7ecf3; --muted:#8a95a5;
    --spoof:#3ddc84; --spoof-ink:#08130c; --real:#4aa8ff; --warn:#ffb454; --danger:#ff6b6b; --focus:#5aa9ff;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  }
  @media (prefers-color-scheme: light){
    :root{ --bg:#eef1f5; --surface:#fff; --surface-2:#f4f7fb; --border:#dde3ec; --text:#141a22; --muted:#5b6675; }
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font-family:var(--sans);-webkit-text-size-adjust:100%}
  body{display:flex;flex-direction:column;overflow:hidden}
  .mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
  button{font-family:inherit;cursor:pointer}
  button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--focus);outline-offset:1px}
  input,select{font-family:inherit}

  .top{display:flex;align-items:center;gap:12px;padding:10px 16px;background:var(--surface);border-bottom:1px solid var(--border)}
  .top .brand{font-weight:700;letter-spacing:.02em;display:flex;align-items:center;gap:8px}
  .top .brand .pin{width:10px;height:10px;border-radius:50%;background:var(--spoof)}
  .top .tabs{display:flex;gap:4px;margin-left:8px}
  .top .tabs button{background:transparent;border:0;color:var(--muted);padding:7px 12px;border-radius:8px;font-size:14px;font-weight:600}
  .top .tabs button.active{background:var(--surface-2);color:var(--text)}
  .top .spacer{flex:1}
  .top .who{font-size:13px;color:var(--muted)}
  .top .who b{color:var(--text)}
  .top .role{font-size:10px;text-transform:uppercase;letter-spacing:.08em;padding:2px 7px;border:1px solid var(--border);border-radius:999px;color:var(--muted);margin-left:6px}
  .top .logout{background:var(--surface-2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:7px 12px;font-size:13px;font-weight:600}

  .discbar{padding:10px 16px;background:color-mix(in srgb,var(--warn) 20%,var(--surface));border-bottom:1px solid color-mix(in srgb,var(--warn) 45%,var(--border));color:var(--text);font-size:13px;line-height:1.45;display:flex;align-items:flex-start;gap:9px}
  .discbar .ic{flex:none;font-size:15px;line-height:1.3}
  .discbar b{color:var(--warn)}

  .wrap{flex:1;min-height:0;display:flex}
  #map{flex:1;min-height:0;background:var(--surface-2)}
  .leaflet-container{background:var(--surface-2)}
  .side{width:360px;max-width:42vw;border-left:1px solid var(--border);background:var(--surface);display:flex;flex-direction:column;min-height:0}
  .side .head{padding:12px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
  .side .head h2{margin:0;font-size:14px;flex:1}
  .side .head button{background:var(--spoof);color:var(--spoof-ink);border:0;border-radius:8px;padding:8px 12px;font-size:13px;font-weight:700}
  .list{overflow:auto;flex:1;min-height:0}
  .empty{padding:24px 16px;color:var(--muted);font-size:14px;line-height:1.5}

  .dev{padding:12px 14px;border-bottom:1px solid var(--border);cursor:pointer}
  .dev:hover{background:var(--surface-2)}
  .dev.sel{background:color-mix(in srgb,var(--spoof) 9%,var(--surface))}
  .dev .r1{display:flex;align-items:center;gap:8px}
  .dev .name{font-weight:600;font-size:14px;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .dev .online{width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none}
  .dev .online.on{background:var(--spoof)}
  .dev .owner{font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:1px 7px}
  .dev .r2{display:flex;gap:12px;margin-top:6px;font-size:12px;color:var(--muted)}
  .dev .badge{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:2px 7px;border-radius:999px}
  .dev .badge.spoof{color:var(--spoof);background:color-mix(in srgb,var(--spoof) 15%,transparent)}
  .dev .badge.real{color:var(--warn);background:color-mix(in srgb,var(--warn) 15%,transparent)}
  .dev .badge.report{color:var(--real);background:color-mix(in srgb,var(--real) 16%,transparent)}

  .detail{border-top:1px solid var(--border);padding:12px 14px;overflow:auto;max-height:56%}
  .detail.hidden{display:none}
  .detail h3{margin:0 0 10px;font-size:13px;display:flex;align-items:center;gap:8px}
  .detail h3 input{flex:1;background:var(--surface-2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:7px 9px;font-size:14px;font-weight:600}
  .searchrow{display:flex;gap:6px;margin-bottom:8px}
  .searchrow input{flex:1;background:var(--surface-2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px;font-size:14px}
  .searchrow button{background:var(--surface-2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:0 12px;font-size:13px;font-weight:600}
  .results{border:1px solid var(--border);border-radius:8px;max-height:120px;overflow:auto;margin-bottom:8px;display:none}
  .results.show{display:block}
  .results div{padding:8px 10px;font-size:12px;border-bottom:1px solid var(--border)}
  .results div:last-child{border-bottom:0}
  .params{display:flex;gap:8px;margin-bottom:10px}
  .params label{flex:1;display:flex;flex-direction:column;gap:4px;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
  .params input{background:var(--surface-2);border:1px solid var(--border);color:var(--text);border-radius:7px;padding:8px;font-size:14px;font-family:var(--mono)}
  .readout{display:flex;gap:16px;margin-bottom:10px;font-size:12px}
  .readout .lbl{color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.06em}
  .readout .val{font-family:var(--mono);font-size:12px}
  .readout .val.spoof{color:var(--spoof)} .readout .val.real{color:var(--real)}
  .row{display:flex;gap:8px;margin-bottom:8px}
  .row .btn{flex:1;padding:11px;border:0;border-radius:9px;font-size:14px;font-weight:700}
  .btn-save{background:var(--spoof);color:var(--spoof-ink)}
  .btn-toggle{background:var(--surface-2);color:var(--text);border:1px solid var(--border)!important;flex:0 0 auto!important;padding:11px 14px!important}
  .cfg{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:8px 0;padding:8px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px}
  .cfg #dt_copymodurl{background:var(--spoof);color:var(--spoof-ink);border-color:transparent;font-weight:700}
  .cfg code{flex:1;min-width:0;font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .cfg button{background:transparent;border:1px solid var(--border);color:var(--text);border-radius:7px;padding:5px 9px;font-size:11px;font-weight:600}
  .minis{display:flex;gap:8px}
  .minis button{flex:1;background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:8px;font-size:12px;font-weight:600}
  .minis button.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 40%,var(--border))}
  .reportbox{display:flex;align-items:center;gap:10px;margin:10px 0;padding:10px;border:1px solid var(--border);border-radius:9px;background:var(--surface-2)}
  .reportbox.on{border-color:color-mix(in srgb,var(--warn) 50%,var(--border));background:color-mix(in srgb,var(--warn) 12%,var(--surface-2))}
  .reportbox .rb-txt{flex:1;display:flex;flex-direction:column;gap:2px;font-size:12px;color:var(--muted)}
  .reportbox .rb-txt b{font-size:13px;color:var(--text)}
  .reportbox button{flex:none;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:8px 12px;font-size:13px;font-weight:600}
  .reportbox button.on{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,var(--border))}

  .users{flex:1;overflow:auto;padding:16px;max-width:720px}
  .users h2{margin:0 0 12px;font-size:16px}
  .utable{width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px}
  .utable th,.utable td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--border)}
  .utable th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
  .utable .role{font-size:10px;text-transform:uppercase;padding:2px 7px;border:1px solid var(--border);border-radius:999px;color:var(--muted)}
  .utable button{background:transparent;border:1px solid var(--border);border-radius:7px;padding:5px 9px;font-size:12px;color:var(--text)}
  .utable button.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 40%,var(--border))}
  .newuser{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px}
  .newuser label{display:flex;flex-direction:column;gap:4px;font-size:11px;color:var(--muted)}
  .newuser input,.newuser select{background:var(--surface-2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px;font-size:14px}
  .newuser .add{background:var(--spoof);color:var(--spoof-ink);border:0;border-radius:8px;padding:10px 16px;font-weight:700;font-size:14px}

  .login{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:24px;background:var(--bg)}
  .login .card{width:100%;max-width:340px;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px}
  .login h1{margin:0 0 4px;font-size:18px;display:flex;align-items:center;gap:8px}
  .login h1 .pin{width:12px;height:12px;border-radius:50%;background:var(--spoof)}
  .login p{margin:0 0 18px;color:var(--muted);font-size:13px}
  .login input{width:100%;background:var(--surface-2);border:1px solid var(--border);color:var(--text);border-radius:10px;padding:12px;font-size:16px;margin-bottom:10px}
  .login button{width:100%;background:var(--spoof);color:var(--spoof-ink);border:0;border-radius:10px;padding:13px;font-weight:700;font-size:15px}
  .login .err{color:var(--danger);font-size:13px;margin-bottom:10px;display:none}
  .login .err.show{display:block}

  .toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#000;color:#fff;padding:11px 16px;border-radius:10px;font-size:14px;opacity:0;transition:opacity .25s;pointer-events:none;z-index:9999;max-width:90vw;text-align:center}
  .toast.show{opacity:.95}
  .hidden{display:none!important}
  @media (max-width:760px){
    .wrap{flex-direction:column} .side{width:100%;max-width:none;border-left:0;border-top:1px solid var(--border);max-height:52%}
    #map{min-height:200px} .detail{max-height:none}
  }
</style>
</head>
<body>

<div class="login" id="login">
  <div class="card">
    <h1><span class="pin"></span> Control Panel</h1>
    <p>Sign in to manage device locations.</p>
    <div class="err" id="loginErr">Invalid username or password.</div>
    <input id="li_user" placeholder="username" autocomplete="username">
    <input id="li_pass" type="password" placeholder="password" autocomplete="current-password">
    <button id="li_btn">Sign in</button>
  </div>
</div>

<div id="app" class="hidden" style="display:flex;flex-direction:column;height:100%">
  <div class="top">
    <div class="brand"><span class="pin"></span> Control Panel</div>
    <div class="tabs">
      <button id="tab_map" class="active">Map</button>
      <button id="tab_users" class="hidden">Users</button>
    </div>
    <div class="spacer"></div>
    <div class="who"><b id="who_name">—</b><span class="role" id="who_role"></span></div>
    <button class="logout" id="logout">Sign out</button>
  </div>

  <div class="discbar hidden" id="discbar"></div>

  <div class="wrap" id="view_map">
    <div id="map"></div>
    <div class="side">
      <div class="head"><h2>Devices</h2><button id="addDev">+ Add device</button></div>
      <div class="list" id="devList"></div>
      <div class="detail hidden" id="detail"></div>
    </div>
  </div>

  <div class="users hidden" id="view_users"></div>
</div>

<div class="toast" id="toast"></div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
function $(id){return document.getElementById(id);}
function toast(t){var e=$("toast");e.textContent=t;e.classList.add("show");setTimeout(function(){e.classList.remove("show");},1900);}
function api(method,path,body){
  return fetch(path,{method:method,headers:body?{"Content-Type":"application/json"}:{},body:body?JSON.stringify(body):undefined,credentials:"same-origin"})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,status:r.status,body:j};}).catch(function(){return {ok:r.ok,status:r.status,body:{}};});});
}
function haversine(a,b){
  if(!a||!b)return null;
  var R=6371000,toR=Math.PI/180;
  var dLat=(b.lat-a.lat)*toR,dLng=(b.lng-a.lng)*toR;
  var s=Math.sin(dLat/2)*Math.sin(dLat/2)+Math.cos(a.lat*toR)*Math.cos(b.lat*toR)*Math.sin(dLng/2)*Math.sin(dLng/2);
  return 2*R*Math.asin(Math.sqrt(s));
}
function fmtDist(m){ if(m==null)return "—"; if(m<1000)return Math.round(m)+" m"; return (m/1000).toFixed(m<10000?1:0)+" km"; }
function ago(ts){ if(!ts)return "never"; var s=Math.floor((Date.now()-ts)/1000);
  if(s<60)return s+"s ago"; if(s<3600)return Math.floor(s/60)+"m ago"; if(s<86400)return Math.floor(s/3600)+"h ago"; return Math.floor(s/86400)+"d ago"; }
function online(d){ return d.lastSeen && (Date.now()-d.lastSeen)<120000; }
function esc(s){ return String(s==null?"":s).replace(/[&<>"]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];}); }

var ME={username:"",role:"user"};
var DEVICES=[];
var SEL=null;
var map, layers={};
var pendMk=null, PENDING=null;
var MODULE_TMPL=${JSON.stringify(MODULE_TEMPLATE)};

function doLogin(){
  var u=$("li_user").value.trim(), p=$("li_pass").value;
  if(!u||!p)return;
  api("POST","/api/login",{username:u,password:p}).then(function(r){
    if(r.ok){ $("loginErr").classList.remove("show"); boot(); }
    else $("loginErr").classList.add("show");
  });
}
$("li_btn").addEventListener("click",doLogin);
$("li_pass").addEventListener("keydown",function(e){if(e.key==="Enter")doLogin();});
$("li_user").addEventListener("keydown",function(e){if(e.key==="Enter")$("li_pass").focus();});
$("logout").addEventListener("click",function(){ api("POST","/api/logout",null).then(function(){location.reload();}); });

$("tab_map").addEventListener("click",function(){ setTab("map"); });
$("tab_users").addEventListener("click",function(){ setTab("users"); });
function setTab(t){
  $("tab_map").classList.toggle("active",t==="map");
  $("tab_users").classList.toggle("active",t==="users");
  $("view_map").classList.toggle("hidden",t!=="map");
  $("view_users").classList.toggle("hidden",t!=="users");
  if(t==="map"&&map)setTimeout(function(){map.invalidateSize();},50);
  if(t==="users")renderUsers();
}

function boot(){
  api("GET","/api/me").then(function(r){
    if(!r.ok){ $("login").classList.remove("hidden"); $("app").classList.add("hidden"); return; }
    ME=r.body;
    $("login").classList.add("hidden"); $("app").classList.remove("hidden");
    $("who_name").textContent=ME.username;
    $("who_role").textContent=ME.role;
    $("tab_users").classList.toggle("hidden",ME.role!=="admin");
    initMap();
    refresh();
    setInterval(refresh,15000);
  });
}
$("addDev").addEventListener("click",addDevice);

function initMap(){
  if(map)return;
  map=L.map("map",{zoomControl:true}).setView([44.4268,26.1025],11);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{maxZoom:19,attribution:"© OpenStreetMap"}).addTo(map);
  map.on("click",function(e){ if(SEL) setSpoofFromMap(e.latlng.lat,e.latlng.lng); });
}

function refresh(){
  return api("GET","/api/devices").then(function(r){
    if(!r.ok)return;
    DEVICES=r.body.devices||[];
    renderList(); drawMap(); renderDisclosure();
    if(SEL){ var d=byId(SEL); if(d) renderDetail(d); else { SEL=null; clearPending(); $("detail").classList.add("hidden"); } }
  });
}
function byId(id){ for(var i=0;i<DEVICES.length;i++)if(DEVICES[i].id===id)return DEVICES[i]; return null; }

// Prominent, always-on banner whenever any visible device is reporting its real
// location. Owners see it for their own devices, so collection is never silent.
function renderDisclosure(){
  var bar=$("discbar"); if(!bar)return;
  var on=DEVICES.filter(function(d){return d.reportReal;});
  if(!on.length){ bar.classList.add("hidden"); bar.innerHTML=""; return; }
  var names=on.map(function(d){return esc(d.name);}).join(", ");
  var msg;
  if(ME.role==="admin"){
    msg='<b>Real-location reporting is ON</b> for '+on.length+' device'+(on.length>1?'s':'')+': '+names+'. Device owners see this same notice.';
  } else {
    msg='<b>Your real location is being shared</b> with the panel administrators for: '+names+'. This device sends its actual GPS here. Turn it off with the "Report real location" switch in the device panel.';
  }
  bar.innerHTML='<span class="ic">📍</span><span>'+msg+'</span>';
  bar.classList.remove("hidden");
}

function renderList(){
  var box=$("devList");
  if(!DEVICES.length){ box.innerHTML='<div class="empty">No devices yet. Add one, then point its module configUrl at the token it gives you.</div>'; return; }
  box.innerHTML="";
  DEVICES.forEach(function(d){
    var sp=d.spoofed?{lat:d.spoofed.latitude,lng:d.spoofed.longitude}:null;
    var rl=d.real?{lat:d.real.latitude,lng:d.real.longitude}:null;
    var dist=haversine(rl,sp);
    var el=document.createElement("div");
    el.className="dev"+(d.id===SEL?" sel":"");
    var ownerTag = (ME.role==="admin") ? '<span class="owner">'+esc(d.owner)+'</span>' : '';
    el.innerHTML=
      '<div class="r1"><span class="online '+(online(d)?"on":"")+'"></span>'+
      '<span class="name">'+esc(d.name)+'</span>'+ownerTag+
      '<span class="badge '+(d.enabled?"spoof":"real")+'">'+(d.enabled?"spoof":"real GPS")+'</span>'+
      (d.reportReal?'<span class="badge report">reporting</span>':'')+'</div>'+
      '<div class="r2"><span>seen '+ago(d.lastSeen)+'</span>'+
      (rl?'<span>real to spoof '+fmtDist(dist)+'</span>':'<span>real: not reported</span>')+'</div>';
    el.addEventListener("click",function(){ select(d.id); });
    box.appendChild(el);
  });
}

function select(id){ if(SEL!==id)clearPending(); SEL=id; renderList(); var d=byId(id); if(d){ renderDetail(d); focusDevice(d); } }
function focusDevice(d){
  var pts=[]; if(d.spoofed)pts.push([d.spoofed.latitude,d.spoofed.longitude]);
  if(d.real)pts.push([d.real.latitude,d.real.longitude]);
  if(pts.length===1)map.setView(pts[0],14);
  else if(pts.length===2)map.fitBounds(pts,{padding:[60,60]});
}
// Dashed hollow-green marker for a picked-but-unsaved point, so the choice shows
// on the map immediately instead of only after Save.
function showPending(la,lo){
  if(!map)return;
  if(!pendMk){
    pendMk=L.circleMarker([la,lo],{radius:9,color:"#3ddc84",fillColor:"#3ddc84",fillOpacity:.28,weight:2,dashArray:"3 3"})
      .bindTooltip("unsaved",{direction:"top"}).addTo(map);
  } else pendMk.setLatLng([la,lo]);
}
function clearPending(){ PENDING=null; if(pendMk&&map){ map.removeLayer(pendMk); } pendMk=null; }

function drawMap(){
  Object.keys(layers).forEach(function(id){ if(!byId(id)){ map.removeLayer(layers[id]); delete layers[id]; } });
  DEVICES.forEach(function(d){
    if(layers[d.id]){ map.removeLayer(layers[d.id]); }
    var g=L.layerGroup();
    var sp=d.spoofed, rl=d.real, sel=(d.id===SEL);
    if(sp&&sp.latitude!=null){
      L.circleMarker([sp.latitude,sp.longitude],{radius:sel?9:7,color:"#3ddc84",fillColor:"#3ddc84",fillOpacity:.9,weight:2})
        .bindTooltip(esc(d.name)+" · spoofed",{direction:"top"}).addTo(g);
    }
    if(rl){
      L.circleMarker([rl.latitude,rl.longitude],{radius:sel?8:6,color:"#4aa8ff",fillColor:"#4aa8ff",fillOpacity:.85,weight:2})
        .bindTooltip(esc(d.name)+" · real",{direction:"top"}).addTo(g);
    }
    if(sp&&sp.latitude!=null&&rl){
      L.polyline([[rl.latitude,rl.longitude],[sp.latitude,sp.longitude]],{color:"#8a95a5",weight:1,dashArray:"4 4",opacity:.7}).addTo(g);
    }
    g.addTo(map); layers[d.id]=g;
  });
}

function renderDetail(d){
  var el=$("detail"); el.classList.remove("hidden");
  var rl=d.real, sp=d.spoofed||{};
  el.innerHTML=
    '<h3><input id="dt_name" value="'+esc(d.name)+'"></h3>'+
    '<div class="searchrow"><input id="dt_q" placeholder="Search a place, or tap the map"><button id="dt_search">Search</button></div>'+
    '<div class="results" id="dt_results"></div>'+
    '<div class="readout">'+
      '<div><div class="lbl">Spoofed</div><div class="val spoof" id="dt_spval">'+(sp.latitude!=null?sp.latitude.toFixed(5)+", "+sp.longitude.toFixed(5):"—")+'</div></div>'+
      '<div><div class="lbl">Real</div><div class="val real">'+(rl?rl.latitude.toFixed(5)+", "+rl.longitude.toFixed(5):"not reported")+'</div></div>'+
    '</div>'+
    '<div class="params">'+
      '<label>Alt (m)<input id="dt_alt" type="number" value="'+(sp.altitude!=null?sp.altitude:"")+'"></label>'+
      '<label>H ±m<input id="dt_hacc" type="number" value="'+(sp.horizontalAccuracy!=null?sp.horizontalAccuracy:39)+'"></label>'+
      '<label>V ±m<input id="dt_vacc" type="number" value="'+(sp.verticalAccuracy!=null?sp.verticalAccuracy:1000)+'"></label>'+
    '</div>'+
    '<div class="row"><button class="btn btn-save" id="dt_save">Save location</button>'+
      '<button class="btn btn-toggle" id="dt_toggle">'+(d.enabled?"Real GPS":"Spoof")+'</button></div>'+
    '<div class="cfg"><code id="dt_cfg">'+esc(location.origin)+'/module.sgmodule?token=(hidden)</code>'+
      '<button id="dt_copymodurl">Copy URL</button>'+
      '<button id="dt_copymod">Module text</button>'+
      '<button id="dt_copyurl">configUrl</button></div>'+
    '<div class="reportbox'+(d.reportReal?' on':'')+'">'+
      '<div class="rb-txt"><b>Report real location to panel</b><span>'+
        (d.reportReal?('ON — this device sends its real GPS here'+(rl?' · last fix '+ago(rl.ts):'')):'Off — real location is not collected')+
      '</span></div>'+
      '<button id="dt_report" class="'+(d.reportReal?'on':'')+'">'+(d.reportReal?'Turn off':'Turn on')+'</button>'+
    '</div>'+
    '<div class="minis"><button id="dt_regen">Regenerate token</button><button class="danger" id="dt_delete">Delete device</button></div>';

  $("dt_name").addEventListener("change",function(){ api("POST","/api/devices/"+d.id+"/rename",{name:$("dt_name").value}).then(function(){refresh();}); });
  $("dt_search").addEventListener("click",function(){ searchPlace($("dt_q").value); });
  $("dt_q").addEventListener("keydown",function(e){ if(e.key==="Enter")searchPlace($("dt_q").value); });
  window._setPending=function(la,lo){ PENDING={lat:la,lng:lo}; showPending(la,lo); var rr=$("dt_results"); if(rr)rr.classList.remove("show");
    var sv=$("dt_spval"); if(sv)sv.textContent=la.toFixed(5)+", "+lo.toFixed(5)+" (unsaved)";
    fetchAlt(la,lo).then(function(a){ if(a!=null&&$("dt_alt"))$("dt_alt").value=Math.round(a); }); };
  // Re-show the unsaved marker after an auto-refresh re-renders this panel.
  if(PENDING){ showPending(PENDING.lat,PENDING.lng); var sv0=$("dt_spval"); if(sv0)sv0.textContent=PENDING.lat.toFixed(5)+", "+PENDING.lng.toFixed(5)+" (unsaved)"; }
  $("dt_save").addEventListener("click",function(){
    var la=PENDING?PENDING.lat:sp.latitude, lo=PENDING?PENDING.lng:sp.longitude;
    if(la==null){toast("Pick a point first");return;}
    api("POST","/api/devices/"+d.id+"/spoof",{lat:la,lng:lo,altitude:$("dt_alt").value,horizontalAccuracy:$("dt_hacc").value,verticalAccuracy:$("dt_vacc").value})
      .then(function(r){ if(r.ok){clearPending();toast("Saved — device applies on next location refresh");refresh();}else toast("Save failed"); });
  });
  $("dt_toggle").addEventListener("click",function(){
    var wasEnabled=d.enabled;
    api("POST","/api/devices/"+d.id+"/enable",{enabled:!wasEnabled}).then(function(r){ if(r.ok){toast(wasEnabled?"Set to real GPS passthrough":"Spoofing on");refresh();} });
  });
  $("dt_copymodurl").addEventListener("click",function(){ copyModuleUrl(d.id); });
  $("dt_copymod").addEventListener("click",function(){ copyModule(d.id); });
  $("dt_copyurl").addEventListener("click",function(){ revealAndCopy(d.id); });
  $("dt_regen").addEventListener("click",function(){ if(confirm("Regenerate token? The current configUrl stops working."))
    api("POST","/api/devices/"+d.id+"/token",null).then(function(r){ if(r.ok){toast("New token generated");showToken(r.body.token);} }); });
  $("dt_delete").addEventListener("click",function(){ if(confirm("Delete this device?"))
    api("DELETE","/api/devices/"+d.id,null).then(function(){ SEL=null;clearPending();$("detail").classList.add("hidden");toast("Deleted");refresh(); }); });
  $("dt_report").addEventListener("click",function(){
    var turnOn=!d.reportReal;
    if(turnOn && !confirm("Turn ON real-location reporting for this device? Its actual GPS will be sent to this panel and shown to administrators. The device owner sees a notice while this is on."))return;
    api("POST","/api/devices/"+d.id+"/reportreal",{enabled:turnOn}).then(function(r){ if(r.ok){toast(turnOn?"Real-location reporting ON":"Real-location reporting off");refresh();}else toast("Failed"); });
  });
}
function setSpoofFromMap(la,lo){ if(window._setPending)window._setPending(la,lo); else toast("Select a device first"); }
function revealToken(id){ return api("GET","/api/devices/"+id,null).then(function(r){ if(r.ok)showToken(r.body.token); return r.ok?r.body.token:null; }); }
function showToken(tok){ var c=$("dt_cfg"); if(c)c.textContent=location.origin+"/module.sgmodule?token="+tok; }
function revealAndCopy(id){ revealToken(id).then(function(tok){ if(!tok)return; copyText(location.origin+"/loc.json?token="+tok,"configUrl copied"); }); }
function copyText(t,okMsg){
  if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(t).then(function(){toast(okMsg);}).catch(function(){prompt("Copy:",t);});
  else prompt("Copy:",t);
}
// Build the full [Script] module line for this device: token + its saved coords.
function buildModule(tok,sp){
  sp=sp||{};
  return MODULE_TMPL
    .replace("__LAT__", sp.latitude!=null?sp.latitude:37.3349)
    .replace("__LNG__", sp.longitude!=null?sp.longitude:-122.00902)
    .replace("__HACC__", sp.horizontalAccuracy!=null?sp.horizontalAccuracy:39)
    .replace("__VACC__", sp.verticalAccuracy!=null?sp.verticalAccuracy:1000)
    .replace("__ALT__", sp.altitude!=null?sp.altitude:530)
    .replace("__CFGURL__", location.origin+"/loc.json?token="+tok);
}
function copyModule(id){ revealToken(id).then(function(tok){ if(!tok)return; var d=byId(id); copyText(buildModule(tok,d&&d.spoofed),"Full module copied — paste into Shadowrocket › Modules"); }); }
// Plain "raw"-style module URL for this device (module text + configUrl baked in).
// Paste it into Shadowrocket › Config › Modules › + › add from URL.
function moduleUrl(tok){ return location.origin+"/module.sgmodule?token="+tok; }
function copyModuleUrl(id){ revealToken(id).then(function(tok){ if(!tok)return; copyText(moduleUrl(tok),"Module URL copied — Shadowrocket › Config › Modules › + › paste URL"); }); }
function fetchAlt(la,lo){ return fetch("https://api.open-meteo.com/v1/elevation?latitude="+la+"&longitude="+lo).then(function(r){return r.json();}).then(function(d){return (d&&d.elevation&&d.elevation.length)?d.elevation[0]:null;}).catch(function(){return null;}); }

function searchPlace(q){
  q=(q||"").trim(); if(!q)return;
  fetch("https://nominatim.openstreetmap.org/search?format=json&limit=6&q="+encodeURIComponent(q)).then(function(r){return r.json();}).then(function(a){
    var box=$("dt_results"); if(!box)return; box.innerHTML="";
    if(!a||!a.length){box.classList.remove("show");toast("No results");return;}
    a.forEach(function(it){ var row=document.createElement("div"); row.textContent=it.display_name; row.style.cursor="pointer";
      row.addEventListener("click",function(){ var la=+it.lat,lo=+it.lon; map.setView([la,lo],15); setSpoofFromMap(la,lo); }); box.appendChild(row); });
    box.classList.add("show");
  }).catch(function(){toast("Search failed");});
}

function addDevice(){
  var name=prompt("Device name?","New device"); if(name===null)return;
  var body={name:name||"Device"};
  if(ME.role==="admin"){ var owner=prompt("Owner username (blank = you):",ME.username); if(owner)body.owner=owner; }
  api("POST","/api/devices",body).then(function(r){
    if(!r.ok){toast(r.body.error||"Create failed");return;}
    toast("Device created"); refresh().then(function(){ select(r.body.device.id); showToken(r.body.token); });
  });
}

function renderUsers(){
  if(ME.role!=="admin")return;
  api("GET","/api/users").then(function(r){
    if(!r.ok)return;
    var v=$("view_users"); var rows=r.body.users.map(function(u){
      return '<tr><td>'+esc(u.username)+(u.username===ME.username?' <span style="color:var(--muted)">(you)</span>':'')+'</td>'+
        '<td><span class="role">'+u.role+'</span></td><td>'+u.devices+'</td>'+
        '<td><button data-pw="'+esc(u.username)+'">Reset password</button> '+
        (u.username!==ME.username?'<button class="danger" data-del="'+esc(u.username)+'">Delete</button>':'')+'</td></tr>';
    }).join("");
    v.innerHTML='<h2>Users</h2><table class="utable"><thead><tr><th>User</th><th>Role</th><th>Devices</th><th></th></tr></thead><tbody>'+rows+'</tbody></table>'+
      '<div class="newuser"><label>Username<input id="nu_user"></label><label>Password<input id="nu_pass" type="text"></label>'+
      '<label>Role<select id="nu_role"><option value="user">user</option><option value="admin">admin</option></select></label>'+
      '<button class="add" id="nu_add">Add user</button></div>';
    $("nu_add").addEventListener("click",function(){
      var u=$("nu_user").value.trim(),p=$("nu_pass").value,role=$("nu_role").value;
      if(!u||!p){toast("Username and password required");return;}
      api("POST","/api/users",{username:u,password:p,role:role}).then(function(r){ if(r.ok){toast("User added");renderUsers();}else toast(r.body.error||"Failed"); });
    });
    Array.prototype.forEach.call(v.querySelectorAll("[data-del]"),function(b){ b.addEventListener("click",function(){
      var u=b.getAttribute("data-del"); if(confirm("Delete user "+u+" and all their devices?"))
        api("DELETE","/api/users/"+encodeURIComponent(u),null).then(function(){toast("Deleted");renderUsers();refresh();}); }); });
    Array.prototype.forEach.call(v.querySelectorAll("[data-pw]"),function(b){ b.addEventListener("click",function(){
      var u=b.getAttribute("data-pw"); var p=prompt("New password for "+u+":"); if(!p)return;
      api("POST","/api/users/"+encodeURIComponent(u)+"/password",{password:p}).then(function(){toast("Password updated");}); }); });
  });
}

boot();
</script>
</body>
</html>`;

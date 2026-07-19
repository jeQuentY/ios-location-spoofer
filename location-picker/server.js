// Location control panel — multi-user admin dashboard.
//
// v2: PostgreSQL storage (see db.js) + real-time SSE (see sse.js). The frontend
// lives in public/index.html. This file is the HTTP routing / auth layer.
//
// Roles:
//   admin  — sees and manages every device and every user
//   user   — sees and manages only their own devices
//
// Each DEVICE has its own token. The Shadowrocket/Surge/Loon module points its
//   configUrl=  at  https://host/loc.json?token=DEVICE_TOKEN
// and the (modified) location-spoofer.js POSTs the real coordinates it read
// from Apple's response to  https://host/report?token=DEVICE_TOKEN  so the
// dashboard can show real vs spoofed side by side, live.
//
// Environment variables:
//   DATABASE_URL    required. Postgres connection string (Coolify provides one).
//   PGSSL           set to "require" for a managed DB that needs TLS.
//   ADMIN_USER      default "admin". Seed admin username (first boot only).
//   ADMIN_PASS      required on first boot to create the admin. Ignored after.
//   SESSION_SECRET  optional. Cookie-signing secret. Auto-generated + persisted
//                   in the DB (meta table) if not provided.
//   PORT            default 8080
//   HOST            default 0.0.0.0
//   CERT, KEY       optional built-in HTTPS (leave unset behind a TLS proxy)
//   LEGACY_DATA_FILE  optional path to a pre-2.0 data.json to import once.

const http = require("http");
const https = require("https");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const db = require("./db");
const sse = require("./sse");

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || "0.0.0.0";
const CERT = process.env.CERT || "";
const KEY = process.env.KEY || "";
const SESSION_TTL = 30 * 24 * 3600 * 1000; // 30 days
const LEGACY_DATA_FILE =
  process.env.LEGACY_DATA_FILE || path.join(__dirname, "data.json");

let SESSION_SECRET = "";

// ---------- crypto ----------
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
// Verify signature + expiry only (sync). Existence of the user is checked async.
function verifyCookie(cookieHeader) {
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
    return o.u;
  } catch (e) {
    return null;
  }
}
async function currentUser(req) {
  const uname = verifyCookie(req.headers.cookie);
  if (!uname) return null;
  const u = await db.getUser(uname);
  if (!u) return null;
  return { username: uname, role: u.role };
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
function readJson(req) {
  return new Promise(function (resolve) {
    let b = "";
    req.on("data", function (c) {
      b += c;
      if (b.length > 1e5) req.destroy();
    });
    req.on("end", function () {
      try {
        resolve(b ? JSON.parse(b) : {});
      } catch (e) {
        resolve(null);
      }
    });
    req.on("error", function () {
      resolve(null);
    });
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
function validCoords(la, lo) {
  return (
    isFinite(la) && isFinite(lo) && la >= -90 && la <= 90 && lo >= -180 && lo <= 180
  );
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
// What the dashboard sees (device token never included here).
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

const DEFAULT_SPOOF = {
  latitude: 37.3349,
  longitude: -122.00902,
  altitude: 530,
  horizontalAccuracy: 39,
  verticalAccuracy: 1000,
};

// ---------- copy-module template (sourced from the real sgmodule) ----------
const EMBEDDED_MODULE = [
  "#!name=iOS Location Spoofer",
  "#!desc=Intercepts Apple's location-service response and replaces the GPS coordinates. For Shadowrocket / Loon / Surge.",
  "#!homepage=https://github.com/jeQuentY/ios-location-spoofer",
  "",
  "[Script]",
  "iOS Location Spoofer = type=http-response,pattern=^https?:\\/\\/(?:gs-loc(?:-cn)?\\.apple\\.com|bluedot\\.is\\.autonavi\\.com(?:\\.gds\\.alibabadns\\.com)?)\\/clls\\/wloc(?:\\?.*)?$,requires-body=1,binary-body-mode=1,max-size=1048576,timeout=10,script-path=https://raw.githubusercontent.com/jeQuentY/ios-location-spoofer/refs/heads/main/location-spoofer.js,argument=mode=response&latitude=37.3349&longitude=-122.00902&horizontalAccuracy=39&verticalAccuracy=1000&altitude=530&debug=false",
  "",
  "[MITM]",
  "hostname = %APPEND% gs-loc.apple.com, gs-loc-cn.apple.com, bluedot.is.autonavi.com, bluedot.is.autonavi.com.gds.alibabadns.com",
].join("\n");

function moduleTextToTemplate(text) {
  let t = String(text)
    .replace(/([?&]latitude=)[^&\r\n]*/, "$1__LAT__")
    .replace(/([?&]longitude=)[^&\r\n]*/, "$1__LNG__")
    .replace(/([?&]horizontalAccuracy=)[^&\r\n]*/, "$1__HACC__")
    .replace(/([?&]verticalAccuracy=)[^&\r\n]*/, "$1__VACC__")
    .replace(/([?&]altitude=)[^&\r\n]*/, "$1__ALT__");
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
      /* try next */
    }
  }
  console.log("Copy-module source: embedded fallback (sgmodule file not found)");
  return moduleTextToTemplate(EMBEDDED_MODULE);
}
const MODULE_TEMPLATE = loadModuleTemplate();

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

// ---------- frontend page (read once at boot, module template injected) ----------
const PAGE = (function () {
  let html;
  try {
    html = fs.readFileSync(path.join(__dirname, "public", "index.html"), "utf8");
  } catch (e) {
    return "<!doctype html><meta charset=utf-8><title>Control Panel</title><p>public/index.html missing.</p>";
  }
  return html.replace("%%MODULE_TEMPLATE_JSON%%", JSON.stringify(MODULE_TEMPLATE));
})();

function sendHtml(res, body) {
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

// ---------- request handler ----------
async function route(req, res) {
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
    const tok = url.searchParams.get("token");
    if (!tok) return json(res, 401, { error: "missing token" });
    const d = await db.getDeviceByToken(tok);
    if (!d) return json(res, 403, { error: "bad token" });
    db.touchLastSeen(d.id, Date.now()).catch(function () {});
    return json(res, 200, spooferView(d));
  }
  if (p === "/report" && m === "POST") {
    const d = await db.getDeviceByToken(url.searchParams.get("token"));
    if (!d) return json(res, 403, { error: "bad token" });
    // Real-location collection is opt-in per device. If not enabled, drop it.
    if (d.reportReal !== true) return json(res, 200, { ok: true, ignored: true });
    const j = await readJson(req);
    if (!j) return json(res, 400, { error: "bad json" });
    const la = Number(j.lat),
      lo = Number(j.lng);
    if (!validCoords(la, lo)) return json(res, 400, { error: "bad coords" });
    const updated = await db.recordReal(d.id, la, lo, j.altitude, Date.now());
    sse.deviceChanged(deviceView(updated));
    return json(res, 200, { ok: true });
  }
  if (p === "/module.sgmodule" && m === "GET") {
    const tok = url.searchParams.get("token");
    if (!tok) return json(res, 401, { error: "missing token" });
    const d = await db.getDeviceByToken(tok);
    if (!d) return json(res, 403, { error: "bad token" });
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    });
    return res.end(fillModule(d, requestOrigin(req)));
  }

  // ===== auth =====
  if (p === "/api/login" && m === "POST") {
    const j = await readJson(req);
    if (!j || !j.username || !j.password)
      return json(res, 400, { error: "missing credentials" });
    const u = await db.getUser(j.username);
    if (!u || !verifyPassword(j.password, u.salt, u.hash))
      return json(res, 401, { error: "invalid login" });
    setSessionCookie(req, res, signSession(j.username), SESSION_TTL);
    return json(res, 200, { username: j.username, role: u.role });
  }
  if (p === "/api/logout" && m === "POST") {
    setSessionCookie(req, res, "", 0);
    return json(res, 200, { ok: true });
  }

  // Everything below requires a session.
  const me = await currentUser(req);
  const isAdmin = !!(me && me.role === "admin");

  // ----- live stream (SSE) -----
  if (p === "/api/stream" && m === "GET") {
    if (!me) return json(res, 401, { error: "not logged in" });
    sse.addClient(req, res, me);
    return; // response stays open
  }

  if (p.indexOf("/api/") === 0) {
    if (!me) return json(res, 401, { error: "not logged in" });

    if (p === "/api/me" && m === "GET")
      return json(res, 200, { username: me.username, role: me.role });

    // ----- devices -----
    if (p === "/api/devices" && m === "GET") {
      const list = (await db.listDevices(me.username, isAdmin)).map(deviceView);
      return json(res, 200, { devices: list, role: me.role, username: me.username });
    }
    if (p === "/api/devices" && m === "POST") {
      const j = await readJson(req);
      if (!j) return json(res, 400, { error: "bad json" });
      let owner = me.username;
      if (isAdmin && j.owner) {
        if (!(await db.getUser(j.owner)))
          return json(res, 400, { error: "no such owner" });
        owner = j.owner;
      }
      const created = await db.createDevice({
        id: newId(),
        name: (j.name || "Device").slice(0, 60),
        owner: owner,
        token: newToken(),
        spoofed: Object.assign({}, DEFAULT_SPOOF),
        createdAt: Date.now(),
      });
      sse.deviceChanged(deviceView(created));
      return json(res, 200, { device: deviceView(created), token: created.token });
    }

    const dm = p.match(/^\/api\/devices\/([a-f0-9]+)(\/[a-z]+)?$/);
    if (dm) {
      const d = await db.getDevice(dm[1]);
      if (!d) return json(res, 404, { error: "no such device" });
      if (!isAdmin && d.owner !== me.username)
        return json(res, 403, { error: "not yours" });
      const sub = dm[2] || "";

      if (sub === "" && m === "GET")
        return json(res, 200, { device: deviceView(d), token: d.token });
      if (sub === "" && m === "DELETE") {
        await db.deleteDevice(d.id);
        sse.deviceRemoved(d.id, d.owner);
        return json(res, 200, { ok: true });
      }
      if (sub === "/history" && m === "GET") {
        return json(res, 200, {
          history: await db.deviceHistory(d.id, url.searchParams.get("limit")),
        });
      }
      if (sub === "/spoof" && m === "POST") {
        const j = await readJson(req);
        if (!j) return json(res, 400, { error: "bad json" });
        const la = Number(j.lat),
          lo = Number(j.lng);
        if (!validCoords(la, lo)) return json(res, 400, { error: "bad coords" });
        const s = Object.assign({}, d.spoofed, { latitude: la, longitude: lo });
        ["altitude", "horizontalAccuracy", "verticalAccuracy"].forEach(function (k) {
          if (j[k] !== undefined && j[k] !== null && j[k] !== "" && isFinite(Number(j[k])))
            s[k] = Math.round(Number(j[k]));
        });
        const updated = await db.updateDeviceSpoof(d.id, s);
        sse.deviceChanged(deviceView(updated));
        return json(res, 200, { device: deviceView(updated) });
      }
      if (sub === "/enable" && m === "POST") {
        const j = await readJson(req);
        const updated = await db.setDeviceEnabled(d.id, !(j && j.enabled === false));
        sse.deviceChanged(deviceView(updated));
        return json(res, 200, { device: deviceView(updated) });
      }
      if (sub === "/rename" && m === "POST") {
        const j = await readJson(req);
        if (j && j.name) {
          const updated = await db.renameDevice(d.id, String(j.name).slice(0, 60));
          sse.deviceChanged(deviceView(updated));
          return json(res, 200, { device: deviceView(updated) });
        }
        return json(res, 200, { device: deviceView(d) });
      }
      if (sub === "/token" && m === "POST") {
        const updated = await db.setDeviceToken(d.id, newToken());
        sse.deviceChanged(deviceView(updated));
        return json(res, 200, { token: updated.token });
      }
      if (sub === "/reportreal" && m === "POST") {
        const j = await readJson(req);
        const updated = await db.setReportReal(d.id, !!(j && j.enabled === true));
        sse.deviceChanged(deviceView(updated));
        return json(res, 200, { device: deviceView(updated) });
      }
      return json(res, 404, { error: "not found" });
    }

    // ----- users (admin only) -----
    if (p === "/api/users") {
      if (!isAdmin) return json(res, 403, { error: "admin only" });
      if (m === "GET") return json(res, 200, { users: await db.listUsers() });
      if (m === "POST") {
        const j = await readJson(req);
        if (!j || !j.username || !j.password)
          return json(res, 400, { error: "missing fields" });
        if (await db.getUser(j.username))
          return json(res, 400, { error: "user exists" });
        const pw = hashPassword(j.password);
        await db.createUser({
          username: j.username,
          role: j.role === "admin" ? "admin" : "user",
          salt: pw.salt,
          hash: pw.hash,
          createdAt: Date.now(),
        });
        sse.usersChanged();
        return json(res, 200, { ok: true });
      }
    }
    const um = p.match(/^\/api\/users\/([^\/]+)(\/password)?$/);
    if (um) {
      if (!isAdmin) return json(res, 403, { error: "admin only" });
      const uname = decodeURIComponent(um[1]);
      if (!(await db.getUser(uname)))
        return json(res, 404, { error: "no such user" });
      if (um[2] === "/password" && m === "POST") {
        const j = await readJson(req);
        if (!j || !j.password)
          return json(res, 400, { error: "missing password" });
        const pw = hashPassword(j.password);
        await db.setUserPassword(uname, pw.salt, pw.hash);
        return json(res, 200, { ok: true });
      }
      if (m === "DELETE") {
        if (uname === me.username)
          return json(res, 400, { error: "cannot delete yourself" });
        // Broadcast removal of the user's devices so live admin maps drop them.
        const owned = await db.listDevices(uname, false);
        await db.deleteUser(uname);
        owned.forEach(function (d) {
          sse.deviceRemoved(d.id, uname);
        });
        sse.usersChanged();
        return json(res, 200, { ok: true });
      }
    }

    return json(res, 404, { error: "not found" });
  }

  if (p === "/" && m === "GET") return sendHtml(res, PAGE);
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
}

function handler(req, res) {
  route(req, res).catch(function (err) {
    console.error("Request error: " + (err && err.message));
    if (!res.headersSent) json(res, 500, { error: "server error" });
    else
      try {
        res.end();
      } catch (e) {}
  });
}

// ---------- boot ----------
async function ensureSessionSecret() {
  SESSION_SECRET = process.env.SESSION_SECRET || (await db.getMeta("sessionSecret")) || "";
  if (!SESSION_SECRET) {
    SESSION_SECRET = crypto.randomBytes(32).toString("hex");
    await db.setMeta("sessionSecret", SESSION_SECRET);
  }
}
async function seedAdmin() {
  if ((await db.countUsers()) > 0) return;
  const au = process.env.ADMIN_USER || "admin";
  const ap = process.env.ADMIN_PASS || "";
  if (!ap) {
    console.error(
      "Startup failed: no users yet and ADMIN_PASS is not set.\n" +
        "Seed the admin on first boot, e.g.:  ADMIN_PASS=$(openssl rand -hex 12) node server.js",
    );
    process.exit(1);
  }
  const pw = hashPassword(ap);
  await db.createUser({
    username: au,
    role: "admin",
    salt: pw.salt,
    hash: pw.hash,
    createdAt: Date.now(),
  });
  console.log('Seeded admin user "' + au + '".');
}

function onListenError(err) {
  if (err.code === "EADDRINUSE")
    console.error("Startup failed: port " + PORT + " is in use.");
  else if (err.code === "EACCES")
    console.error("Startup failed: no permission for port " + PORT + ".");
  else console.error("Startup failed: " + err.message);
  process.exit(1);
}
function startServer() {
  if (CERT && KEY) {
    try {
      const server = https.createServer(
        { cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) },
        handler,
      );
      server.on("error", onListenError);
      setInterval(function () {
        try {
          server.setSecureContext({
            cert: fs.readFileSync(CERT),
            key: fs.readFileSync(KEY),
          });
        } catch (e) {
          console.log("cert reload failed: " + e.message);
        }
      }, 12 * 3600 * 1000);
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

(async function main() {
  try {
    await db.init({ legacyDataFile: LEGACY_DATA_FILE });
    await ensureSessionSecret();
    await seedAdmin();
    startServer();
  } catch (err) {
    console.error("Startup failed: " + (err && err.message));
    process.exit(1);
  }
})();

// Location picker — single file, zero dependencies (Node built-ins only)
// Serves a map UI to choose a point and writes it to loc.json, which the
// Shadowrocket / Surge / Loon / QX / Stash location-spoofer script reads.
//
// Map layers: OpenStreetMap + Esri satellite (WGS-84) and AutoNavi vector /
// satellite (GCJ-02, for China) with automatic GCJ-02 <-> WGS-84 conversion.
// Search lists candidates (pans only); tap map / drag pin to move the point;
// nothing is written until you press "Save location". Altitude is auto-filled
// from terrain; altitude / accuracy can be adjusted by hand.
//
// Environment variables:
//   TOKEN       required. Access token. Process exits if unset (no weak default).
//   PORT        default 8080
//   HOST        default 0.0.0.0
//   DATA_FILE   default ./loc.json  (point at a mounted volume to persist)
//   CERT, KEY   optional. Paths to fullchain + private key for built-in HTTPS.
//               Leave unset when a reverse proxy (Coolify/Traefik) terminates TLS.
//
// Run (HTTP, proxy handles TLS — the Coolify case):
//   TOKEN=$(openssl rand -hex 24) PORT=8080 node server.js
//
// Run (built-in HTTPS, reusing existing certs):
//   TOKEN=... PORT=8443 CERT=/path/fullchain.pem KEY=/path/privkey.pem node server.js
//
// Then append to your Shadowrocket module's argument line:
//   &configUrl=https://your-domain/loc.json?token=YOUR_TOKEN
//
// The URL must carry ?token=<TOKEN>. Missing token -> 401; wrong token -> 403.

const http = require("http");
const https = require("https");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || "0.0.0.0";
// TOKEN is mandatory: exit rather than fall back to a weak default, otherwise
// anyone who finds the URL could read and rewrite your device's location.
const TOKEN = process.env.TOKEN || "";
if (!TOKEN) {
  console.error(
    "Startup failed: TOKEN environment variable is not set.\n" +
      "Start with a random secret, e.g.:\n" +
      "  TOKEN=$(openssl rand -hex 24) PORT=8080 node server.js",
  );
  process.exit(1);
}
const CERT = process.env.CERT || "";
const KEY = process.env.KEY || "";
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "loc.json");

// Constant-time compare so response timing can't be used to guess the token.
function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// Field names / defaults match DEFAULT_CONFIG in location-spoofer.js.
const DEFAULT = {
  enabled: true, // false = script passes the real response through
  latitude: 37.3349,
  longitude: -122.00902,
  altitude: 530,
  horizontalAccuracy: 39,
  verticalAccuracy: 1000,
};

function readLoc() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch (e) {
    return Object.assign({}, DEFAULT);
  }
}

// Atomic write: write a temp file then rename, so a crash mid-write can't
// leave loc.json truncated and unreadable by the spoofer script.
function writeLoc(obj) {
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

function send(res, code, type, body) {
  res.writeHead(code, {
    "Content-Type": type,
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

// Distinguish "no token" (401, guide the caller) from "wrong token" (403).
function checkToken(token, res) {
  if (token == null || token === "") {
    send(
      res,
      401,
      "application/json",
      '{"error":"missing token","hint":"add ?token=<TOKEN> to the URL (must match the TOKEN env var)"}',
    );
    return false;
  }
  if (!safeEqual(token, TOKEN)) {
    send(res, 403, "application/json", '{"error":"bad token"}');
    return false;
  }
  return true;
}

function readBody(req, cb) {
  let body = "";
  req.on("data", function (c) {
    body += c;
    if (body.length > 1e4) req.destroy();
  });
  req.on("end", function () {
    cb(body);
  });
}

function handler(req, res) {
  const url = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  const token = url.searchParams.get("token");

  // Health check (no token) — point Coolify's health check here.
  if (url.pathname === "/healthz" && req.method === "GET") {
    return send(res, 200, "application/json", '{"status":"ok"}');
  }

  // Favicon: 204 so browsers stop logging a 404 (tab icon is set in the HTML).
  if (url.pathname === "/favicon.ico") {
    res.writeHead(204);
    return res.end();
  }

  // Shadowrocket reads coordinates here (stored as WGS-84, what Apple expects).
  if (url.pathname === "/loc.json" && req.method === "GET") {
    if (!checkToken(token, res)) return;
    return send(res, 200, "application/json", JSON.stringify(readLoc()));
  }

  // Web UI saves a point (already converted to WGS-84 client-side).
  if (url.pathname === "/set" && req.method === "POST") {
    if (!checkToken(token, res)) return;
    readBody(req, function (body) {
      try {
        const j = JSON.parse(body);
        const la = Number(j.lat);
        const lo = Number(j.lng);
        if (
          !isFinite(la) ||
          !isFinite(lo) ||
          la < -90 ||
          la > 90 ||
          lo < -180 ||
          lo > 180
        ) {
          return send(res, 400, "application/json", '{"error":"bad coords"}');
        }
        const cur = readLoc();
        cur.enabled = true; // saving a new point implies spoofing on
        cur.latitude = la;
        cur.longitude = lo;
        function setInt(key, v) {
          if (
            v !== undefined &&
            v !== null &&
            v !== "" &&
            isFinite(Number(v))
          ) {
            cur[key] = Math.round(Number(v));
          }
        }
        setInt("altitude", j.altitude);
        setInt("horizontalAccuracy", j.horizontalAccuracy);
        setInt("verticalAccuracy", j.verticalAccuracy);
        writeLoc(cur);
        return send(res, 200, "application/json", JSON.stringify(cur));
      } catch (e) {
        return send(res, 400, "application/json", '{"error":"bad json"}');
      }
    });
    return;
  }

  // Toggle: spoof vs pass through real GPS.
  if (url.pathname === "/enable" && req.method === "POST") {
    if (!checkToken(token, res)) return;
    readBody(req, function (body) {
      try {
        const j = JSON.parse(body);
        const cur = readLoc();
        cur.enabled = j.enabled !== false;
        writeLoc(cur);
        return send(res, 200, "application/json", JSON.stringify(cur));
      } catch (e) {
        return send(res, 400, "application/json", '{"error":"bad json"}');
      }
    });
    return;
  }

  // Map page. Served without a token check — it holds no secrets and every
  // sensitive call it makes is token-gated. The page prompts for the token
  // and validates it by calling /loc.json.
  if (url.pathname === "/" && req.method === "GET") {
    return send(res, 200, "text/html; charset=utf-8", PAGE);
  }

  return send(res, 404, "text/plain", "not found");
}

function onListenError(err) {
  if (err.code === "EADDRINUSE") {
    console.error(
      "Startup failed: port " + PORT + " is in use. Pick a free PORT.",
    );
  } else if (err.code === "EACCES") {
    console.error(
      "Startup failed: no permission to bind port " +
        PORT +
        " (ports below 1024 need root).",
    );
  } else {
    console.error("Startup failed: " + err.message);
  }
  process.exit(1);
}

function start() {
  // Make sure the data directory exists (e.g. a mounted /data volume).
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  } catch (e) {}

  if (CERT && KEY) {
    try {
      const opts = { cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) };
      const server = https.createServer(opts, handler);
      server.on("error", onListenError);
      // Hot-reload certs every 12h so acme.sh renewals need no restart.
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
      server.listen(PORT, HOST, function () {
        console.log(
          "location picker (https) listening on " + HOST + ":" + PORT,
        );
      });
      return;
    } catch (e) {
      console.log(
        "HTTPS start failed (could not read certs), falling back to HTTP: " +
          e.message,
      );
    }
  }
  const server = http.createServer(handler);
  server.on("error", onListenError);
  server.listen(PORT, HOST, function () {
    console.log("location picker (http) listening on " + HOST + ":" + PORT);
  });
}

start();

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<meta name="color-scheme" content="dark light">
<title>Location Picker</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%233ddc84' d='M12 2C8.1 2 5 5.1 5 9c0 5.2 7 13 7 13s7-7.8 7-13c0-3.9-3.1-7-7-7zm0 9.5A2.5 2.5 0 1 1 12 6.5a2.5 2.5 0 0 1 0 5z'/%3E%3C/svg%3E">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
  :root{
    --bg:#0e1116; --surface:#161b22; --surface-2:#1c232c; --border:#2a323d;
    --text:#e6ebf2; --muted:#8b96a5;
    --accent:#3ddc84; --accent-ink:#08130c;
    --warn:#ffb454; --warn-ink:#2a1c05;
    --danger:#ff6b6b; --focus:#5aa9ff;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  }
  @media (prefers-color-scheme: light){
    :root{
      --bg:#f2f4f7; --surface:#ffffff; --surface-2:#f6f8fb; --border:#dbe1ea;
      --text:#141a22; --muted:#5b6675; --accent-ink:#08130c; --warn-ink:#3a2705;
    }
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font-family:var(--sans);-webkit-text-size-adjust:100%}
  body{display:flex;flex-direction:column;overflow:hidden}
  .mono{font-family:var(--mono);font-variant-numeric:tabular-nums}

  /* Status banner — the one thing you glance at */
  .status{display:flex;align-items:center;gap:12px;padding:12px 14px;border-bottom:1px solid var(--border);
    background:var(--surface);transition:background .2s}
  body.real .status{background:linear-gradient(0deg,var(--surface),var(--surface)),color-mix(in srgb,var(--warn) 12%,var(--surface))}
  body.spoof .status{background:color-mix(in srgb,var(--accent) 10%,var(--surface))}
  .dot{width:11px;height:11px;border-radius:50%;flex:none;background:var(--muted)}
  body.spoof .dot{background:var(--accent);box-shadow:0 0 0 0 color-mix(in srgb,var(--accent) 70%,transparent);animation:pulse 2s infinite}
  body.real .dot{background:var(--warn)}
  @keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--accent) 55%,transparent)}70%{box-shadow:0 0 0 9px transparent}100%{box-shadow:0 0 0 0 transparent}}
  @media (prefers-reduced-motion:reduce){.dot{animation:none!important}}
  .status .txt{display:flex;flex-direction:column;min-width:0;flex:1}
  .status .label{font-size:12px;font-weight:700;letter-spacing:.09em;text-transform:uppercase}
  body.spoof .status .label{color:var(--accent)}
  body.real .status .label{color:var(--warn)}
  .status .coord{font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .status .badge{font-size:11px;font-weight:600;padding:3px 8px;border-radius:999px;border:1px solid var(--border);color:var(--muted);flex:none}
  .status .badge.on{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 45%,var(--border))}
  .status .badge.off{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,var(--border))}

  /* Search */
  .bar{display:flex;gap:8px;padding:10px 12px;background:var(--surface);border-bottom:1px solid var(--border)}
  .bar input{flex:1;min-width:0;padding:11px 12px;font-size:16px;color:var(--text);
    background:var(--surface-2);border:1px solid var(--border);border-radius:10px}
  .bar input::placeholder{color:var(--muted)}
  .bar button{padding:0 16px;font-size:15px;font-weight:600;border:0;border-radius:10px;
    background:var(--surface-2);color:var(--text);border:1px solid var(--border)}
  .results{background:var(--surface);border-bottom:1px solid var(--border);max-height:34vh;overflow:auto;display:none}
  .results.show{display:block}
  .rrow{padding:11px 14px;font-size:14px;border-bottom:1px solid var(--border);color:var(--text);cursor:pointer}
  .rrow:last-child{border-bottom:0}
  .rrow:active{background:var(--surface-2)}

  #map{flex:1;min-height:0;background:var(--surface-2)}
  .leaflet-container{background:var(--surface-2)}

  /* Control deck */
  .deck{background:var(--surface);border-top:1px solid var(--border);padding:12px 14px 14px}
  .params{display:flex;gap:10px;margin-bottom:12px}
  .params label{flex:1;display:flex;flex-direction:column;gap:4px;font-size:11px;color:var(--muted);letter-spacing:.02em}
  .params input{width:100%;padding:9px 10px;font-size:15px;color:var(--text);
    background:var(--surface-2);border:1px solid var(--border);border-radius:8px;font-family:var(--mono)}
  .actions{display:flex;gap:10px}
  .btn{flex:1;padding:13px;font-size:15px;font-weight:700;border:0;border-radius:10px;cursor:pointer;letter-spacing:.01em}
  .btn-save{background:var(--accent);color:var(--accent-ink)}
  .btn-toggle{background:var(--surface-2);color:var(--text);border:1px solid var(--border);flex:0 0 auto;padding:13px 16px}
  body.real .btn-toggle{background:var(--warn);color:var(--warn-ink);border-color:transparent}
  .config{display:flex;align-items:center;gap:8px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border)}
  .config .k{font-size:11px;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;flex:none}
  .config code{flex:1;min-width:0;font-family:var(--mono);font-size:12px;color:var(--muted);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .config button{font-size:12px;font-weight:600;padding:6px 10px;border:1px solid var(--border);
    border-radius:8px;background:var(--surface-2);color:var(--text);cursor:pointer;flex:none}

  button:focus-visible,input:focus-visible,.rrow:focus-visible{outline:2px solid var(--focus);outline-offset:1px}
  input:focus{border-color:var(--focus)}

  /* Token gate */
  .gate{position:fixed;inset:0;background:var(--bg);display:none;align-items:center;justify-content:center;padding:24px;z-index:5000}
  .gate.show{display:flex}
  .gate .card{width:100%;max-width:360px;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:22px}
  .gate h1{margin:0 0 6px;font-size:17px}
  .gate p{margin:0 0 16px;font-size:13px;color:var(--muted);line-height:1.5}
  .gate input{width:100%;padding:12px;font-size:16px;font-family:var(--mono);color:var(--text);
    background:var(--surface-2);border:1px solid var(--border);border-radius:10px;margin-bottom:12px}
  .gate button{width:100%;padding:13px;font-size:15px;font-weight:700;border:0;border-radius:10px;background:var(--accent);color:var(--accent-ink);cursor:pointer}
  .gate .err{color:var(--danger);font-size:13px;margin-bottom:12px;display:none}
  .gate .err.show{display:block}

  .toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#000;color:#fff;
    padding:11px 16px;border-radius:10px;font-size:14px;opacity:0;transition:opacity .25s;pointer-events:none;z-index:9999;max-width:90vw;text-align:center}
  .toast.show{opacity:.95}
</style>
</head>
<body class="spoof">

<header class="status" id="status">
  <span class="dot"></span>
  <div class="txt">
    <span class="label" id="stateLabel">Spoofing active</span>
    <span class="coord mono" id="coordReadout">—</span>
  </div>
  <span class="badge" id="savedBadge">saved</span>
</header>

<div class="bar">
  <input id="q" placeholder="Search a place, then tap the map to drop the pin" autocomplete="off">
  <button id="btn">Search</button>
</div>
<div class="results" id="results"></div>

<div id="map"></div>

<div class="deck">
  <div class="params">
    <label>Altitude (m)<input id="alt" type="number" inputmode="numeric"></label>
    <label>Horizontal ±m<input id="hacc" type="number" inputmode="numeric"></label>
    <label>Vertical ±m<input id="vacc" type="number" inputmode="numeric"></label>
  </div>
  <div class="actions">
    <button class="btn btn-save" id="savebtn">Save location</button>
    <button class="btn btn-toggle" id="restorebtn">Restore real GPS</button>
  </div>
  <div class="config">
    <span class="k">configUrl</span>
    <code id="cfgUrl">—</code>
    <button id="cfgCopy">Copy</button>
  </div>
</div>

<div class="gate" id="gate">
  <div class="card">
    <h1>Access token</h1>
    <p>Enter the token you set as the <code>TOKEN</code> environment variable. It stays in this browser's URL.</p>
    <div class="err" id="gateErr">Token rejected. Check it matches your TOKEN env var.</div>
    <input id="gateInput" type="password" placeholder="token" autocomplete="off" spellcheck="false">
    <button id="gateBtn">Unlock</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
var token = new URLSearchParams(location.search).get("token") || "";

// ---------- GCJ-02 <-> WGS-84 (China map offset correction) ----------
var GCJ = (function(){
  var PI = Math.PI, a = 6378245.0, ee = 0.00669342162296594323;
  function outOfChina(lat,lng){return (lng<72.004||lng>137.8347)||(lat<0.8293||lat>55.8271);}
  function tLat(x,y){
    var r=-100.0+2.0*x+3.0*y+0.2*y*y+0.1*x*y+0.2*Math.sqrt(Math.abs(x));
    r+=(20.0*Math.sin(6.0*x*PI)+20.0*Math.sin(2.0*x*PI))*2.0/3.0;
    r+=(20.0*Math.sin(y*PI)+40.0*Math.sin(y/3.0*PI))*2.0/3.0;
    r+=(160.0*Math.sin(y/12.0*PI)+320*Math.sin(y*PI/30.0))*2.0/3.0;return r;
  }
  function tLng(x,y){
    var r=300.0+x+2.0*y+0.1*x*x+0.1*x*y+0.1*Math.sqrt(Math.abs(x));
    r+=(20.0*Math.sin(6.0*x*PI)+20.0*Math.sin(2.0*x*PI))*2.0/3.0;
    r+=(20.0*Math.sin(x*PI)+40.0*Math.sin(x/3.0*PI))*2.0/3.0;
    r+=(150.0*Math.sin(x/12.0*PI)+300.0*Math.sin(x/30.0*PI))*2.0/3.0;return r;
  }
  function wgs2gcj(lat,lng){
    if(outOfChina(lat,lng))return [lat,lng];
    var dLat=tLat(lng-105.0,lat-35.0), dLng=tLng(lng-105.0,lat-35.0);
    var radLat=lat/180.0*PI, m=Math.sin(radLat); m=1-ee*m*m; var sm=Math.sqrt(m);
    dLat=(dLat*180.0)/((a*(1-ee))/(m*sm)*PI);
    dLng=(dLng*180.0)/(a/sm*Math.cos(radLat)*PI);
    return [lat+dLat,lng+dLng];
  }
  function gcj2wgs(lat,lng){ // iterative inverse, round-trip error < 0.001 m
    if(outOfChina(lat,lng))return [lat,lng];
    var wlat=lat, wlng=lng;
    for(var i=0;i<3;i++){ var g=wgs2gcj(wlat,wlng); wlat+=lat-g[0]; wlng+=lng-g[1]; }
    return [wlat,wlng];
  }
  return {wgs2gcj:wgs2gcj, gcj2wgs:gcj2wgs};
})();

// ---------- state ----------
var map, marker;
var WGS = {lat:0, lng:0};   // pin's true WGS-84 value (preview; maybe unsaved)
var datum = "wgs";          // base layer datum: 'gcj' (AutoNavi) or 'wgs'
var saved = true;
var enabledState = true;    // true = spoofing; false = real GPS passthrough

function $(id){return document.getElementById(id);}
function toast(t){var e=$("toast");e.textContent=t;e.classList.add("show");setTimeout(function(){e.classList.remove("show");},1900);}
function numOrNull(id){var v=$(id).value.trim();return v===""?null:Number(v);}

function render(){
  document.body.classList.toggle("spoof",enabledState);
  document.body.classList.toggle("real",!enabledState);
  if(!enabledState){
    $("stateLabel").textContent="Real GPS — passthrough";
    $("coordReadout").textContent="Script is not modifying location";
    $("savedBadge").className="badge off";
    $("savedBadge").textContent="real";
    $("restorebtn").textContent="Resume spoofing";
    return;
  }
  $("stateLabel").textContent="Spoofing active";
  $("coordReadout").textContent=WGS.lat.toFixed(5)+", "+WGS.lng.toFixed(5)+"  ·  "+($("alt").value||"?")+" m";
  $("savedBadge").className="badge "+(saved?"on":"off");
  $("savedBadge").textContent=saved?"saved":"unsaved";
  $("restorebtn").textContent="Restore real GPS";
}

function toggleEnabled(){
  var want = !enabledState;
  fetch("/enable?token="+encodeURIComponent(token),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled:want})})
    .then(function(r){
      if(r.ok){ enabledState=want; render();
        toast(want ? "Spoofing on — toggle Location Services to apply" : "Real GPS restored — toggle Location Services to apply"); }
      else toast("Toggle failed ("+r.status+")");
    })
    .catch(function(){ toast("Network error"); });
}

function dispPos(){return datum==="gcj"?GCJ.wgs2gcj(WGS.lat,WGS.lng):[WGS.lat,WGS.lng];}
function toWgs(lat,lng){return datum==="gcj"?GCJ.gcj2wgs(lat,lng):[lat,lng];}

// Terrain altitude via open-meteo elevation API (expects WGS-84).
function fetchElevation(lat,lng){
  return fetch("https://api.open-meteo.com/v1/elevation?latitude="+lat+"&longitude="+lng)
    .then(function(r){return r.json();})
    .then(function(d){return (d&&d.elevation&&d.elevation.length)?d.elevation[0]:null;})
    .catch(function(){return null;});
}

// Move the pin (preview only, not saved).
function movePin(dispLat,dispLng){
  var w=toWgs(dispLat,dispLng);
  WGS={lat:w[0], lng:w[1]};
  saved=false;
  marker.setLatLng([dispLat,dispLng]);
  render();
  fetchElevation(WGS.lat,WGS.lng).then(function(el){ if(el!==null)$("alt").value=Math.round(el); render(); });
}

// Save the pin to the device (writes loc.json).
function commit(){
  var payload={lat:WGS.lat, lng:WGS.lng,
    altitude:numOrNull("alt"), horizontalAccuracy:numOrNull("hacc"), verticalAccuracy:numOrNull("vacc")};
  fetch("/set?token="+encodeURIComponent(token),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)})
    .then(function(r){ if(r.ok){ saved=true; enabledState=true; render(); toast("Saved — toggle Location Services to apply"); } else { toast("Save failed ("+r.status+")"); } })
    .catch(function(){ toast("Network error"); });
}

// Search: list candidates; selecting one only pans the map.
function search(){
  var q=$("q").value.trim(); if(!q) return;
  fetch("https://nominatim.openstreetmap.org/search?format=json&addressdetails=0&limit=8&q="+encodeURIComponent(q))
    .then(function(r){return r.json();})
    .then(function(a){
      var box=$("results"); box.innerHTML="";
      if(!a||!a.length){ box.classList.remove("show"); toast("No results"); return; }
      a.forEach(function(it){
        var row=document.createElement("div");
        row.className="rrow"; row.setAttribute("tabindex","0");
        row.textContent=it.display_name;
        function pick(){
          box.classList.remove("show"); box.innerHTML="";
          var la=+it.lat, lo=+it.lon;
          var p = datum==="gcj"?GCJ.wgs2gcj(la,lo):[la,lo];
          map.setView(p,15);
          toast("Panned — tap the map to place the pin");
        }
        row.addEventListener("click",pick);
        row.addEventListener("keydown",function(e){if(e.key==="Enter")pick();});
        box.appendChild(row);
      });
      box.classList.add("show");
    })
    .catch(function(){toast("Search failed");});
}

function buildLayers(){
  var osm=L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{maxZoom:19,attribution:"© OpenStreetMap"});
  osm.datum="wgs";
  var esri=L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",{maxZoom:19,attribution:"© Esri"});
  esri.datum="wgs";
  var amapVec=L.tileLayer("https://wprd0{s}.is.autonavi.com/appmaptile?x={x}&y={y}&z={z}&lang=en&size=1&scl=1&style=7",{subdomains:"1234",maxZoom:18,attribution:"AutoNavi"});
  amapVec.datum="gcj";
  var amapSat=L.layerGroup([
    L.tileLayer("https://webst0{s}.is.autonavi.com/appmaptile?style=6&x={x}&y={y}&z={z}",{subdomains:"1234",maxZoom:18}),
    L.tileLayer("https://wprd0{s}.is.autonavi.com/appmaptile?x={x}&y={y}&z={z}&lang=en&size=1&scl=1&style=8",{subdomains:"1234",maxZoom:18})
  ]);
  amapSat.datum="gcj";
  return {
    "OpenStreetMap":osm, "Satellite (Esri)":esri,
    "AutoNavi vector (China)":amapVec, "AutoNavi satellite (China)":amapSat,
    _default:osm
  };
}

function copyConfigUrl(){
  var u=location.origin+"/loc.json?token="+encodeURIComponent(token);
  function done(){toast("configUrl copied");}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(u).then(done).catch(function(){prompt("Copy this configUrl:",u);});}
  else prompt("Copy this configUrl:",u);
}

function init(){
  var layers=buildLayers();
  $("cfgUrl").textContent="…/loc.json?token=•••";

  map=L.map("map",{zoomControl:true});
  layers._default.addTo(map); datum="wgs";
  map.setView(dispPos(),13);
  var ctl={}; for(var k in layers){ if(k!=="_default") ctl[k]=layers[k]; }
  L.control.layers(ctl,null,{collapsed:true}).addTo(map);

  marker=L.marker(dispPos(),{draggable:true}).addTo(map);
  render();

  map.on("baselayerchange",function(e){datum=e.layer.datum||"wgs"; var p=dispPos(); marker.setLatLng(p); map.setView(p,map.getZoom()); render();});
  map.on("click",function(e){movePin(e.latlng.lat,e.latlng.lng);});
  marker.on("dragend",function(){var p=marker.getLatLng(); movePin(p.lat,p.lng);});
}

function load(){
  fetch("/loc.json?token="+encodeURIComponent(token)).then(function(r){
    if(r.status===401||r.status===403){ showGate(true); throw new Error("auth"); }
    return r.json();
  }).then(function(d){
    WGS={lat:d.latitude, lng:d.longitude};
    saved=true;
    enabledState=(d.enabled!==false);
    $("alt").value=(d.altitude!==undefined?d.altitude:"");
    $("hacc").value=(d.horizontalAccuracy!==undefined?d.horizontalAccuracy:39);
    $("vacc").value=(d.verticalAccuracy!==undefined?d.verticalAccuracy:1000);
    init();
  }).catch(function(e){ if(e.message!=="auth") toast("Load failed — check the server"); });
}

// ---------- token gate ----------
function showGate(isError){
  $("gateErr").classList.toggle("show",!!isError);
  $("gate").classList.add("show");
  $("gateInput").focus();
}
function submitGate(){
  var v=$("gateInput").value.trim();
  if(!v) return;
  location.href=location.pathname+"?token="+encodeURIComponent(v);
}

$("btn").addEventListener("click",search);
$("q").addEventListener("keydown",function(e){if(e.key==="Enter")search();});
$("savebtn").addEventListener("click",commit);
$("restorebtn").addEventListener("click",toggleEnabled);
$("cfgCopy").addEventListener("click",copyConfigUrl);
$("gateBtn").addEventListener("click",submitGate);
$("gateInput").addEventListener("keydown",function(e){if(e.key==="Enter")submitGate();});

if(!token){ showGate(false); }
else { load(); }
</script>
</body>
</html>`;

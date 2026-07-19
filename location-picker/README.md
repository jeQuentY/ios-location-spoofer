# Location Control Panel

A self-hosted, multi-user control panel for the iOS location spoofer. One panel
serves every device: admins manage all users and see every device on a live map;
each user manages only their own devices. Each device has its own token, so the
phone reads its spoof coordinates from **your** panel instead of a static file on
`raw.githubusercontent.com`.

- **Storage:** PostgreSQL
- **Realtime:** Server-Sent Events (the admin map updates instantly, no refresh)
- **Frontend:** single page, Leaflet map, mobile-first, dark/light
- **Deploy:** Docker → Coolify (or `docker compose` on any VPS)

> Replaces the old single-token Cloudflare Worker variants. This is now the only
> web UI.

## What it does

| Piece | Purpose |
|------|---------|
| `server.js` | HTTP routing, auth (signed-cookie sessions, scrypt passwords), SSE hub |
| `db.js` | PostgreSQL layer — users, devices, real-location history, schema migration |
| `sse.js` | Live push of device changes, filtered per role |
| `public/index.html` | The dashboard (map, device list, users tab) |

### Endpoints

Device-facing (authenticated by a per-device token):

| Path | Method | Purpose |
|------|--------|---------|
| `/loc.json?token=` | GET | the module reads spoof coordinates from here (`configUrl`) |
| `/report?token=` | POST | the script posts the **real** pre-spoof coordinates here (only if the panel enabled it) |
| `/module.sgmodule?token=` | GET | the full importable module with this device's `configUrl` baked in |

Dashboard (authenticated by session cookie): `/api/login`, `/api/logout`,
`/api/me`, `/api/devices` (+ `/spoof` `/enable` `/rename` `/token` `/reportreal`
`/history`), `/api/users` (+ `/password`), and `/api/stream` (SSE). `/healthz` is
open for health checks.

## Deploy on Coolify

1. **Add a PostgreSQL** resource in your project. Coolify gives it an internal
   connection string.
2. **Add an Application** from this Git repo:
   - Build pack: **Dockerfile**
   - Base directory / build context: `location-picker`
   - Dockerfile location: `location-picker/dockerfile`
3. **Environment variables** on the application:
   - `DATABASE_URL` = the Postgres connection string from step 1
     (e.g. `postgres://user:pass@<service>:5432/db`)
   - `ADMIN_PASS` = a strong password — **used only on the very first boot** to
     create the `admin` user, then ignored. (`ADMIN_USER` optional, default `admin`.)
   - `PGSSL=require` only if your Postgres needs TLS (most Coolify-internal DBs don't).
4. Deploy. Coolify terminates TLS for you, so leave `CERT`/`KEY` unset.
5. Open the app URL, sign in as `admin`, and create your users under the **Users** tab.

After first boot you can remove `ADMIN_PASS` from the environment.

### Local / VPS with docker compose

```bash
cd location-picker
ADMIN_PASS=$(openssl rand -hex 12) docker compose up --build
# → http://localhost:8080   (user "admin", that password)
```

### Bare Node (you supply Postgres)

```bash
cd location-picker
npm install
DATABASE_URL=postgres://user:pass@localhost:5432/panel \
ADMIN_PASS=$(openssl rand -hex 12) node server.js
```

## Put a device on a phone

1. In the dashboard, **+ Add** a device (admins can assign it to any user).
2. Open the device, tap **▦ QR** and scan it in Shadowrocket — or use **Module URL**
   and, in Shadowrocket, go to **Config › Modules › + › from URL** and paste it.
3. Pick a location by tapping the map (or search a place), then **Save location**.
   The device applies it on its next location refresh (toggle iOS Location Services
   off/on to force it; Loon/Shadowrocket refresh the cache within ~60s).

Because the module's `configUrl` points at `/loc.json?token=…` on your panel, the
coordinates are always live from here — no editing files, no `raw.github`.

## Real-location reporting (opt-in, disclosed)

Each device has a **Report real location** switch (off by default). When an
owner or admin turns it on:

- the panel sets `reportReal:true` in that device's `/loc.json`,
- the on-device script then POSTs the pre-spoof coordinates it read from Apple to
  `/report`, and the map shows **real (blue)** next to **spoofed (green)**.

While it's on, a banner is shown to the device owner too — collection is never
silent. Turning it off deletes the stored real fix and its history.

## Environment variables

| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | — | **required.** Postgres connection string. |
| `PGSSL` | off | set `require` for a managed DB that needs TLS. |
| `ADMIN_USER` | `admin` | seed admin username (first boot only). |
| `ADMIN_PASS` | — | seed admin password (first boot only, then ignored). |
| `SESSION_SECRET` | auto | cookie-signing secret; auto-generated + stored in the DB if unset. |
| `PORT` / `HOST` | `8080` / `0.0.0.0` | listen address. |
| `CERT` / `KEY` | — | optional built-in HTTPS; leave unset behind a TLS proxy. |
| `LEGACY_DATA_FILE` | `./data.json` | one-time import of a pre-2.0 JSON store, if present. |

// Tiny Server-Sent Events hub for the live dashboard.
//
// Each connected dashboard opens GET /api/stream (authed by the session cookie)
// and registers here with its { username, role }. When a device changes, the
// HTTP layer calls deviceChanged()/deviceRemoved() and we push it only to the
// clients allowed to see it (admins see everything; users see their own).
//
// Payloads are the same deviceView objects the REST API returns, so the client
// can merge them straight into its device list with no extra round-trip.

const clients = new Set();

function send(client, event, data) {
  try {
    client.res.write("event: " + event + "\n");
    client.res.write("data: " + JSON.stringify(data) + "\n\n");
  } catch (e) {
    // Broken pipe — drop it; the 'close' handler will clean up.
  }
}

function canSee(client, owner) {
  return client.role === "admin" || client.username === owner;
}

// Register a live dashboard. `res` is the HTTP response kept open for SSE.
function addClient(req, res, who) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no", // disable proxy buffering (nginx/Coolify)
  });
  res.write("retry: 3000\n\n");
  const client = { res, username: who.username, role: who.role };
  clients.add(client);

  const hb = setInterval(function () {
    try {
      res.write(": hb\n\n");
    } catch (e) {
      /* ignore */
    }
  }, 25000);

  function close() {
    clearInterval(hb);
    clients.delete(client);
  }
  // Listen on BOTH the request and the response stream. A client that drops the
  // connection can otherwise surface as an unhandled 'error' on the response
  // socket and take the whole process down.
  req.on("close", close);
  req.on("error", close);
  res.on("close", close);
  res.on("error", close);
  send(client, "hello", { ok: true });
  return client;
}

// A device was created or updated. `view` is a deviceView (must include .owner).
function deviceChanged(view) {
  if (!view) return;
  clients.forEach(function (c) {
    if (canSee(c, view.owner)) send(c, "device", view);
  });
}

function deviceRemoved(id, owner) {
  clients.forEach(function (c) {
    if (canSee(c, owner)) send(c, "device-removed", { id: id });
  });
}

// The user list changed (admin-only view). Nudge admins to refetch.
function usersChanged() {
  clients.forEach(function (c) {
    if (c.role === "admin") send(c, "users", {});
  });
}

function clientCount() {
  return clients.size;
}

module.exports = {
  addClient,
  deviceChanged,
  deviceRemoved,
  usersChanged,
  clientCount,
};

/**
 * NEXUS — Social Media App Server
 * 6 WebSocket endpoints powering real features with varying security levels
 *
 * 🔒 SECURE:
 *   /ws/chat        — authenticated DM chat with token auth + rate limit + sanitization
 *   /ws/presence    — who's online (origin-locked, read-only broadcast)
 *
 * ⚠️ MINOR ISSUES:
 *   /ws/feed        — live post feed (no rate limit, weak session, verbose errors)
 *   /ws/notify      — push notifications (any client can trigger alerts for all users)
 *
 * 🚨 CRITICAL:
 *   /ws/prices      — live crypto prices (eval() RCE, leaks process.env)
 *   /ws/comments    — post comments (mass assignment, reflected XSS, log injection)
 */

const http   = require("http");
const ws     = require("ws");
const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");
const url    = require("url");

// ── Static file handler (reused for multiple server instances) ─────────────────
function handleHttpRequest(req, res) {
  let filePath = path.join(__dirname, "public", req.url === "/" ? "index.html" : req.url);
  const ext   = path.extname(filePath);
  const mime  = { ".html":"text/html", ".css":"text/css", ".js":"application/javascript", ".png":"image/png" };
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, { "Content-Type": mime[ext] || "text/plain" });
    res.end(data);
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const VALID_TOKENS = new Set(["token_alice_9f3k2", "token_bob_m7x91", "token_guest_demo"]);
const rateLimits   = new Map();   // ip → { count, reset }
const onlineUsers  = new Map();   // ws → username
const commentLog   = [];

function secureId()  { return crypto.randomBytes(24).toString("hex"); }
function weakId()    { return Math.random().toString(36).slice(2); }
function getIp(req)  { return req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "?"; }
function esc(s)      { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }

function rateOk(ip, limit = 15, windowMs = 10000) {
  const now = Date.now();
  if (!rateLimits.has(ip) || rateLimits.get(ip).reset < now)
    rateLimits.set(ip, { count: 1, reset: now + windowMs });
  else {
    const r = rateLimits.get(ip);
    if (r.count >= limit) return false;
    r.count++;
  }
  return true;
}

function broadcast(wss, data) {
  const str = JSON.stringify(data);
  wss.clients.forEach(c => {
    if (c.readyState !== ws.OPEN) return;
    try {
      c.send(str);
    } catch {
      // Keep demo endpoints alive even if one client has already disconnected.
    }
  });
}

function safeSend(socket, payload) {
  if (!socket || socket.readyState !== ws.OPEN) return;
  try {
    socket.send(typeof payload === "string" ? payload : JSON.stringify(payload));
  } catch {
    // Swallow send errors so fuzzing does not terminate the demo process.
  }
}

const DEMO_VARIANTS = {
  presence: crypto.randomInt(2),
  feed: crypto.randomInt(2),
  notify: crypto.randomInt(2),
  prices: crypto.randomInt(2),
  comments: crypto.randomInt(2),
};

function demoVariant(name) {
  return DEMO_VARIANTS[name] || 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔒 ENDPOINT 1 — /ws/chat  (Secure DM Chat)
//    Token auth · rate limiting · XSS sanitization · crypto session IDs
// ═══════════════════════════════════════════════════════════════════════════════
const wssChat = new ws.Server({ noServer: true });

const rooms = new Map(); // roomId → Set of ws clients

wssChat.on("connection", (socket, req) => {
  socket.authed    = false;
  socket.username  = null;
  socket.sessionId = secureId();
  socket.ip        = getIp(req);
  socket.on("error", () => {});

  safeSend(socket, { type:"system", text:"Send your auth token to begin." });

  socket.on("message", raw => {
    if (!rateOk(socket.ip)) {
      safeSend(socket, { type:"error", text:"Slow down! Rate limit hit." });
      return;
    }
    let msg;
    try { msg = JSON.parse(raw); } catch { safeSend(socket, { type:"error", text:"Bad JSON." }); return; }

    if (!socket.authed) {
      if (msg.type === "auth" && VALID_TOKENS.has(msg.token)) {
        socket.authed   = true;
        socket.username = msg.username ? esc(msg.username).slice(0,20) : "User_" + socket.sessionId.slice(0,6);
        safeSend(socket, { type:"auth_ok", username: socket.username, session: socket.sessionId });
        // announce online
        broadcast(wssChat, { type:"presence", username: socket.username, online: true });
      } else {
        safeSend(socket, { type:"error", text:"Invalid token." });
        socket.close(1008);
      }
      return;
    }

    if (msg.type === "message") {
      if (typeof msg.text !== "string" || msg.text.length > 400) {
        safeSend(socket, { type:"error", text:"Message too long or invalid." });
        return;
      }
      // Sanitize before broadcast
      const clean = esc(msg.text);
      broadcast(wssChat, { type:"message", from: socket.username, text: clean, ts: Date.now() });
    }

    if (msg.type === "typing") {
      broadcast(wssChat, { type:"typing", from: socket.username });
    }
  });

  socket.on("close", () => {
    if (socket.username) broadcast(wssChat, { type:"presence", username: socket.username, online: false });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 🔒 ENDPOINT 2 — /ws/presence  (Online Users — Secure Push-Only)
//    Origin-locked · read-only broadcast · rejects all client input
// ═══════════════════════════════════════════════════════════════════════════════
const wssPresence = new ws.Server({ noServer: true });
let ALLOWED_ORIGIN = "http://localhost:3000";

// Simulate users coming online/offline
const DEMO_USERS = ["alice","bob","carol","dave","eve","frank"];
let presenceIdx = 0;
setInterval(() => {
  const user   = DEMO_USERS[presenceIdx % DEMO_USERS.length];
  const online = Math.random() > 0.4;
  broadcast(wssPresence, { type:"presence_update", username: user, online, viewers: Math.floor(Math.random()*120)+10 });
  presenceIdx++;
}, 3000);

wssPresence.on("connection", (socket) => {
  const variant = demoVariant("presence");
  socket.on("error", () => {});
  safeSend(socket, {
    type:"welcome",
    message:"Subscribed to presence feed.",
    users: variant === 0 ? DEMO_USERS : DEMO_USERS.slice(0, 3),
    viewers: variant === 0 ? undefined : Math.floor(Math.random() * 30) + 5,
  });
  socket.on("message", () => {
    safeSend(socket, { type:"error", text:"This is a read-only feed." });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ⚠️ ENDPOINT 3 — /ws/feed  (Live Post Feed — Minor Issues)
//    No rate limit · weak session token · verbose error stack traces · no auth
// ═══════════════════════════════════════════════════════════════════════════════
const wssFeed = new ws.Server({ noServer: true });

const FAKE_POSTS = [
  { user:"alice",    text:"Just shipped a new feature 🚀",           likes:42, img:"🖼️" },
  { user:"bob",      text:"This coffee is carrying me today ☕",      likes:17, img:"📸" },
  { user:"carol",    text:"Anyone else loving the new UI? 🎨",        likes:88, img:"🖼️" },
  { user:"dave",     text:"Hot take: tabs > spaces. Fight me. 🔥",    likes:203, img:null },
  { user:"eve",      text:"Weekend hike was incredible 🏔️",           likes:56, img:"📸" },
  { user:"frank",    text:"New blog post: WebSocket Security 101 📝", likes:31, img:null },
];

let feedIdx = 0;
setInterval(() => {
  const post = { ...FAKE_POSTS[feedIdx % FAKE_POSTS.length], id: Date.now(), ts: Date.now() };
  broadcast(wssFeed, { type:"new_post", post });
  feedIdx++;
}, 4000);

wssFeed.on("connection", (socket, req) => {
  const variant = demoVariant("feed");
  // ⚠️ Weak non-cryptographic session token
  const weakToken = weakId();
  // ⚠️ Exposes server info on connect
  socket.on("error", () => {});
  safeSend(socket, {
    type:"connected",
    sessionToken: weakToken,
    server:"nexus-feed/2.1",
    nodeVersion: variant === 0 ? process.version : undefined,
    build: variant === 0 ? "dev" : "dev-lite",
  });

  socket.on("message", raw => {
    // ⚠️ No rate limiting — flood away
    try {
      const msg = JSON.parse(Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw));
      if (msg && msg.type === "like") {
        // ⚠️ No validation — any post ID, any count accepted
        broadcast(wssFeed, { type:"like_update", postId: msg.postId, likes: msg.likes });
      }
      if (msg && msg.type === "post") {
        // ⚠️ No auth, no sanitization, anyone can post
        broadcast(wssFeed, { type:"new_post", post: { user: msg.username || "anonymous", text: msg.text, likes:0, ts: Date.now(), id: Date.now() } });
      }
    } catch(e) {
      // ⚠️ Full stack trace returned to client
      safeSend(socket, {
        type:"error",
        message: e.message,
        stack: variant === 0 ? e.stack : undefined,
        hint:"Check your JSON syntax"
      });
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ⚠️ ENDPOINT 4 — /ws/notify  (Push Notifications — Minor Issues)
//    Any client can push alerts to everyone · no auth · no message validation
// ═══════════════════════════════════════════════════════════════════════════════
const wssNotify = new ws.Server({ noServer: true });
const notifyClients = new Set();

// Server-side legit notifications
setInterval(() => {
  const alerts = [
    { icon:"❤️",  text:"alice liked your post" },
    { icon:"💬",  text:"bob commented on your photo" },
    { icon:"👥",  text:"3 new followers today" },
    { icon:"🔔",  text:"carol mentioned you in a post" },
  ];
  const alert = alerts[Math.floor(Math.random() * alerts.length)];
  broadcast(wssNotify, { type:"notification", ...alert, ts: Date.now(), source:"server" });
}, 6000);

wssNotify.on("connection", (socket) => {
  const variant = demoVariant("notify");
  notifyClients.add(socket);
  socket.on("error", () => {});
  safeSend(socket, { type:"subscribed", message:"Notification feed active." });

  socket.on("message", raw => {
    try {
      const msg = JSON.parse(Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw));
      if (msg && msg.type === "push") {
        // ⚠️ ANY connected client can push a notification to EVERYONE
        // ⚠️ Text not validated or sanitized
        notifyClients.forEach(c => {
          if (c.readyState === ws.OPEN) {
            try {
              c.send(JSON.stringify({
                type:"notification",
                icon: msg.icon || "📢",
                text: msg.text,
                ts: Date.now(),
                source: variant === 0 ? "client" : "client-broadcast"
              }));
            } catch {
              // Ignore disconnected clients.
            }
          }
        });
      }
      // ⚠️ Unknown types silently swallowed
    } catch {
      // ⚠️ For demo stability, acknowledge malformed JSON instead of closing.
      safeSend(socket, { type:"error", text:"Bad JSON." });
    }
  });
  socket.on("close", () => notifyClients.delete(socket));
});

// ═══════════════════════════════════════════════════════════════════════════════
// 🚨 ENDPOINT 5 — /ws/prices  (Live Crypto Prices — CRITICAL)
//    eval() RCE · leaks process.env · no auth · reflects raw input
// ═══════════════════════════════════════════════════════════════════════════════
const wssPrices = new ws.Server({ noServer: true });

// Simulate live price ticker
const prices = { BTC: 62000, ETH: 3100, SOL: 145, NEXUS: 4.20 };
setInterval(() => {
  Object.keys(prices).forEach(k => {
    prices[k] = +(prices[k] * (0.995 + Math.random() * 0.01)).toFixed(2);
  });
  broadcast(wssPrices, { type:"price_update", prices, ts: Date.now() });
}, 2000);

wssPrices.on("connection", (socket) => {
  const variant = demoVariant("prices");
  // 🚨 Sends ALL environment variables to every client that connects
  socket.on("error", () => {});
  safeSend(socket, {
    type:"welcome",
    prices,
    env: variant === 0 ? process.env : undefined,
    envKeys: variant === 0 ? undefined : Object.keys(process.env).slice(0, 10)
  });

  socket.on("message", raw => {
    try {
      const msg = JSON.parse(Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw));
      if (msg && msg.type === "calculate") {
        // 🚨 CRITICAL: eval() runs ANY JavaScript on the server
        try {
          const result = eval(msg.expression); // eslint-disable-line no-eval
          safeSend(socket, { type:"calc_result", expression: msg.expression, result: String(result) });
        } catch(e) {
          safeSend(socket, { type:"calc_error", message: e.message, stack: e.stack });
        }
      }
      if (msg && msg.type === "alert_price") {
        // No validation — accepted silently
        safeSend(socket, { type:"alert_set", coin: msg.coin, target: msg.target });
      }
    } catch {
      // 🚨 Reflects raw unescaped user input back as a string
      safeSend(socket, { type:"error", raw: String(raw) });
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 🚨 ENDPOINT 6 — /ws/comments  (Post Comments — CRITICAL)
//    Mass assignment privilege escalation · reflected XSS · log injection
// ═══════════════════════════════════════════════════════════════════════════════
const wssComments = new ws.Server({ noServer: true });

wssComments.on("connection", (socket, req) => {
  const variant = demoVariant("comments");
  // 🚨 Default session — client can overwrite any field including role
  socket.session = { role: "guest", username: "anonymous", ip: getIp(req), verified: false };
  socket.on("error", () => {});
  safeSend(socket, { type:"session", session: socket.session });

  socket.on("message", raw => {
    try {
      const msg = JSON.parse(Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw));

      if (msg && msg.type === "set_profile") {
        // 🚨 MASS ASSIGNMENT — Object.assign lets client set role:"admin", verified:true, etc.
        if (msg.data && typeof msg.data === "object") {
          if (variant === 0) {
            Object.assign(socket.session, msg.data);
          } else {
            Object.assign(socket.session, {
              username: msg.data.username || socket.session.username,
              role: msg.data.role || socket.session.role,
              verified: !!msg.data.verified,
            });
          }
        }
        safeSend(socket, { type:"profile_updated", session: socket.session });
      }

      if (msg && msg.type === "comment") {
        // 🚨 Raw user HTML stored in log and reflected back — XSS
        const entry = {
          ts:       new Date().toISOString(),
          username: socket.session.username,
          role:     socket.session.role,
          text:     String(msg.text ?? "")   // 🚨 no sanitization
        };
        commentLog.push(entry);
        // 🚨 Reflects raw input directly with string concat — breaks JSON, XSS
        safeSend(socket, { type:"comment_posted", text: entry.text, role: socket.session.role });
        broadcast(wssComments, { type:"new_comment", ...entry });
      }

      if (msg && msg.type === "get_comments") {
        // 🚨 Exposes full log including IPs and roles
        safeSend(socket, {
          type:"comments",
          data: variant === 0 ? commentLog : commentLog.map(entry => ({
            ts: entry.ts,
            username: entry.username,
            role: entry.role,
            text: entry.text,
          }))
        });
      }

      if (msg && msg.type === "search") {
        // 🚨 Log injection — user-controlled string goes into search results
        const query = String(msg.query ?? "");
        const results = commentLog.filter(e => e.text && e.text.includes(query));
        safeSend(socket, { type:"search_results", query, results });
      }

    } catch {
      // Keep malformed payloads from crashing the demo while still returning something.
      safeSend(socket, { type:"error", raw: String(raw) });
    }
  });
});

// ── Upgrade router ────────────────────────────────────────────────────────────
function attachUpgradeHandler(serverInstance, port) {
  serverInstance.on("upgrade", (req, socket, head) => {
    const { pathname } = url.parse(req.url);

    if (pathname === "/ws/presence") {
      const origin = req.headers.origin || "";
      const allowedOrigin = `http://localhost:${port}`;
      if (origin !== allowedOrigin) {
        socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
        socket.destroy();
        return;
      }
    }

    const routes = {
      "/ws/chat":     wssChat,
      "/ws/presence": wssPresence,
      "/ws/feed":     wssFeed,
      "/ws/notify":   wssNotify,
      "/ws/prices":   wssPrices,
      "/ws/comments": wssComments,
    };

    const wss = routes[pathname];
    if (wss) wss.handleUpgrade(req, socket, head, c => wss.emit("connection", c, req));
    else socket.destroy();
  });
}

// Create and start independent server instances on a fixed set of ports
function createAndStartInstance(port) {
  const instance = http.createServer(handleHttpRequest);
  attachUpgradeHandler(instance, port);

  instance.on('error', err => {
    if (err.code === 'EADDRINUSE') {
      console.error(`Port ${port} is already in use — skipping this instance.`);
      return;
    }
    throw err;
  });

  instance.listen(port, () => {
    console.log(`\n✅  NEXUS running at → http://localhost:${port}\n`);
    console.log("WebSocket endpoints:");
    console.log("  🔒  /ws/chat      Secure DM Chat");
    console.log("  🔒  /ws/presence  Secure Online Presence");
    console.log("  ⚠️   /ws/feed      Live Post Feed  (minor issues)");
    console.log("  ⚠️   /ws/notify    Push Notifications  (minor issues)");
    console.log("  🚨  /ws/prices    Crypto Prices  (CRITICAL — RCE via eval)");
    console.log("  🚨  /ws/comments  Comments  (CRITICAL — XSS + mass assignment)\n");
  });

  return instance;
}

const portToStart = Number(process.env.PORT) || 3000;
createAndStartInstance(portToStart);

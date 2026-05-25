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

// ── Static file server ────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  let filePath = path.join(__dirname, "public", req.url === "/" ? "index.html" : req.url);
  const ext   = path.extname(filePath);
  const mime  = { ".html":"text/html", ".css":"text/css", ".js":"application/javascript", ".png":"image/png" };
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, { "Content-Type": mime[ext] || "text/plain" });
    res.end(data);
  });
});

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
  wss.clients.forEach(c => { if (c.readyState === ws.OPEN) c.send(str); });
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

  socket.send(JSON.stringify({ type:"system", text:"Send your auth token to begin." }));

  socket.on("message", raw => {
    if (!rateOk(socket.ip)) {
      socket.send(JSON.stringify({ type:"error", text:"Slow down! Rate limit hit." }));
      return;
    }
    let msg;
    try { msg = JSON.parse(raw); } catch { socket.send(JSON.stringify({ type:"error", text:"Bad JSON." })); return; }

    if (!socket.authed) {
      if (msg.type === "auth" && VALID_TOKENS.has(msg.token)) {
        socket.authed   = true;
        socket.username = msg.username ? esc(msg.username).slice(0,20) : "User_" + socket.sessionId.slice(0,6);
        socket.send(JSON.stringify({ type:"auth_ok", username: socket.username, session: socket.sessionId }));
        // announce online
        broadcast(wssChat, { type:"presence", username: socket.username, online: true });
      } else {
        socket.send(JSON.stringify({ type:"error", text:"Invalid token." }));
        socket.close(1008);
      }
      return;
    }

    if (msg.type === "message") {
      if (typeof msg.text !== "string" || msg.text.length > 400) {
        socket.send(JSON.stringify({ type:"error", text:"Message too long or invalid." }));
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
const ALLOWED_ORIGIN = "http://localhost:3000";

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
  socket.send(JSON.stringify({ type:"welcome", message:"Subscribed to presence feed.", users: DEMO_USERS }));
  socket.on("message", () => {
    socket.send(JSON.stringify({ type:"error", text:"This is a read-only feed." }));
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
  // ⚠️ Weak non-cryptographic session token
  const weakToken = weakId();
  // ⚠️ Exposes server info on connect
  socket.send(JSON.stringify({ type:"connected", sessionToken: weakToken, server:"nexus-feed/2.1", nodeVersion: process.version }));

  socket.on("message", raw => {
    // ⚠️ No rate limiting — flood away
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "like") {
        // ⚠️ No validation — any post ID, any count accepted
        broadcast(wssFeed, { type:"like_update", postId: msg.postId, likes: msg.likes });
      }
      if (msg.type === "post") {
        // ⚠️ No auth, no sanitization, anyone can post
        broadcast(wssFeed, { type:"new_post", post: { user: msg.username || "anonymous", text: msg.text, likes:0, ts: Date.now(), id: Date.now() } });
      }
    } catch(e) {
      // ⚠️ Full stack trace returned to client
      socket.send(JSON.stringify({ type:"error", message: e.message, stack: e.stack, hint:"Check your JSON syntax" }));
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
  notifyClients.add(socket);
  socket.send(JSON.stringify({ type:"subscribed", message:"Notification feed active." }));

  socket.on("message", raw => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "push") {
        // ⚠️ ANY connected client can push a notification to EVERYONE
        // ⚠️ Text not validated or sanitized
        notifyClients.forEach(c => {
          if (c.readyState === ws.OPEN)
            c.send(JSON.stringify({ type:"notification", icon: msg.icon || "📢", text: msg.text, ts: Date.now(), source:"client" }));
        });
      }
      // ⚠️ Unknown types silently swallowed
    } catch {
      // ⚠️ Silent fail, no error reported
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
  // 🚨 Sends ALL environment variables to every client that connects
  socket.send(JSON.stringify({ type:"welcome", prices, env: process.env }));

  socket.on("message", raw => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "calculate") {
        // 🚨 CRITICAL: eval() runs ANY JavaScript on the server
        try {
          const result = eval(msg.expression); // eslint-disable-line no-eval
          socket.send(JSON.stringify({ type:"calc_result", expression: msg.expression, result: String(result) }));
        } catch(e) {
          socket.send(JSON.stringify({ type:"calc_error", message: e.message, stack: e.stack }));
        }
      }
      if (msg.type === "alert_price") {
        // No validation — accepted silently
        socket.send(JSON.stringify({ type:"alert_set", coin: msg.coin, target: msg.target }));
      }
    } catch {
      // 🚨 Reflects raw unescaped user input back as a string
      socket.send(`{"type":"error","raw":"${raw}"}`);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 🚨 ENDPOINT 6 — /ws/comments  (Post Comments — CRITICAL)
//    Mass assignment privilege escalation · reflected XSS · log injection
// ═══════════════════════════════════════════════════════════════════════════════
const wssComments = new ws.Server({ noServer: true });

wssComments.on("connection", (socket, req) => {
  // 🚨 Default session — client can overwrite any field including role
  socket.session = { role: "guest", username: "anonymous", ip: getIp(req), verified: false };
  socket.send(JSON.stringify({ type:"session", session: socket.session }));

  socket.on("message", raw => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === "set_profile") {
        // 🚨 MASS ASSIGNMENT — Object.assign lets client set role:"admin", verified:true, etc.
        Object.assign(socket.session, msg.data);
        socket.send(JSON.stringify({ type:"profile_updated", session: socket.session }));
      }

      if (msg.type === "comment") {
        // 🚨 Raw user HTML stored in log and reflected back — XSS
        const entry = {
          ts:       new Date().toISOString(),
          username: socket.session.username,
          role:     socket.session.role,
          text:     msg.text   // 🚨 no sanitization
        };
        commentLog.push(entry);
        // 🚨 Reflects raw input directly with string concat — breaks JSON, XSS
        socket.send(`{"type":"comment_posted","text":"${msg.text}","role":"${socket.session.role}"}`);
        broadcast(wssComments, { type:"new_comment", ...entry });
      }

      if (msg.type === "get_comments") {
        // 🚨 Exposes full log including IPs and roles
        socket.send(JSON.stringify({ type:"comments", data: commentLog }));
      }

      if (msg.type === "search") {
        // 🚨 Log injection — user-controlled string goes into search results
        const results = commentLog.filter(e => e.text && e.text.includes(msg.query));
        socket.send(JSON.stringify({ type:"search_results", query: msg.query, results }));
      }

    } catch {
      socket.send(raw.toString()); // 🚨 raw reflection
    }
  });
});

// ── Upgrade router ────────────────────────────────────────────────────────────
server.on("upgrade", (req, socket, head) => {
  const { pathname } = url.parse(req.url);

  if (pathname === "/ws/presence") {
    const origin = req.headers.origin || "";
    if (origin !== ALLOWED_ORIGIN) {
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

server.listen(3000, () => {
  console.log("\n✅  NEXUS running at → http://localhost:3000\n");
  console.log("WebSocket endpoints:");
  console.log("  🔒  /ws/chat      Secure DM Chat");
  console.log("  🔒  /ws/presence  Secure Online Presence");
  console.log("  ⚠️   /ws/feed      Live Post Feed  (minor issues)");
  console.log("  ⚠️   /ws/notify    Push Notifications  (minor issues)");
  console.log("  🚨  /ws/prices    Crypto Prices  (CRITICAL — RCE via eval)");
  console.log("  🚨  /ws/comments  Comments  (CRITICAL — XSS + mass assignment)\n");
});

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const multer = require("multer");
const crypto = require("crypto");
const { v4: uuid } = require("uuid");

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3000;
const SUBUSER_KEY = (process.env.SUBUSER_KEY && process.env.SUBUSER_KEY.trim()) || "KO9dYBYW/agAJqRwkHdeLcmzNCabsgM5qkhlqeMahLc";
const ADMIN_KEY = (process.env.ADMIN_KEY && process.env.ADMIN_KEY.trim()) || "root#777";
const WEBHOOK = process.env.DISCORD_WEBHOOK_URL || "";

const DATA = path.join(__dirname, "data");
const FILE_FOLDERS = ["botflood","discordtools","backdoor","opsecgay","discordrat","minecraftcheats"];
const F = {};
["users","chat","announcements","tickets","giveaways","blacklist","iplogs","settings","unlocks","changelog","downloads","codes","audit","folderReqs","sessions"].forEach(n => {
  F[n] = path.join(DATA, n + ".json");
});

function load(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback !== undefined ? fallback : []; }
}
function save(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });
Object.entries(F).forEach(([k, f]) => {
  if (!fs.existsSync(f)) {
    if (k === "settings") save(f, { maintenance: false, maintenanceUntil: null, logo: null, quickLinks: [], newsTicker: [] });
    else if (k === "unlocks" || k === "sessions") save(f, {});
    else save(f, []);
  }
});

function clientIp(req) {
  let ip = req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.socket?.remoteAddress || "";
  return String(ip).split(",")[0].trim().replace(/^::ffff:/, "");
}
function audit(action, actor, meta = {}) {
  const list = load(F.audit, []);
  list.unshift({ id: uuid(), action, actor: actor || "system", meta, at: new Date().toISOString() });
  if (list.length > 1000) list.length = 1000;
  save(F.audit, list);
}
async function webhook(content) {
  if (!WEBHOOK) return;
  try {
    await fetch(WEBHOOK, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: String(content).slice(0, 1800) }) });
  } catch {}
}
function fileHash(fp) {
  try {
    const buf = fs.readFileSync(fp);
    return { md5: crypto.createHash("md5").update(buf).digest("hex"), sha256: crypto.createHash("sha256").update(buf).digest("hex") };
  } catch { return null; }
}

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads"), { index: false, dotfiles: "deny" }));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  name: "opsec.sid",
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.TRUST_SECURE === "1"
  }
}));

app.use((req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString("hex");
  next();
});
function csrfCheck(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const pathName = req.originalUrl.split("?")[0];
  if (["/api/login", "/api/csrf", "/api/health", "/api/public/changelog"].includes(pathName)) return next();
  if (!req.session.user) return next();
  const token = req.headers["x-csrf-token"] || req.headers["x-xsrf-token"] || req.body?._csrf;
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: "CSRF", hint: "GET /api/csrf and retry" });
  }
  next();
}
app.use(csrfCheck);

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: "Too many login attempts" }, keyGenerator: (req) => clientIp(req) || req.ip });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 180, standardHeaders: true, legacyHeaders: false, message: { error: "Rate limited" }, keyGenerator: (req) => clientIp(req) || req.ip });
app.use("/api/", apiLimiter);

const failMap = new Map();
function noteFail(ip) {
  const n = (failMap.get(ip) || 0) + 1;
  failMap.set(ip, n);
  if (n >= 15) {
    const bl = load(F.blacklist, []);
    if (!bl.find(b => b.type === "ip" && b.target === ip)) {
      bl.unshift({ id: uuid(), target: ip, type: "ip", reason: "auto: failed logins", at: new Date().toISOString() });
      save(F.blacklist, bl);
    }
  }
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });
  const users = load(F.users, []);
  const db = users.find(u => u.id === req.session.user.id);
  if (db?.expiresAt && new Date(db.expiresAt) < new Date()) {
    db.canDownload = false;
    save(F.users, users);
    req.session.user.canDownload = false;
  }
  if (db?.isBanned) return res.status(403).json({ error: "Banned" });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user?.isAdmin) return res.status(403).json({ error: "Admin only" });
  next();
}

app.get("/api/csrf", (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString("hex");
  res.json({ token: req.session.csrfToken });
});
app.get("/api/health", (req, res) => {
  const s = load(F.settings, {});
  res.json({ ok: true, maintenance: !!s.maintenance, time: new Date().toISOString() });
});
app.get("/api/public/changelog", (req, res) => res.json(load(F.changelog, []).slice(0, 30)));

app.post("/api/login", loginLimiter, async (req, res) => {
  const key = String(req.body.key || "").trim().replace(/^["']|["']$/g, "");
  const ip = clientIp(req);
  if (!key) return res.status(400).json({ error: "Key required" });
  if (load(F.blacklist, []).find(b => b.type === "ip" && b.target === ip)) {
    return res.status(403).json({ error: "IP blacklisted" });
  }

  let user = null;
  if (key === ADMIN_KEY) {
    user = { id: "admin-root", username: "root", isAdmin: true, isBanned: false, canDownload: true, role: "admin", registered: new Date().toISOString() };
  } else if (key === SUBUSER_KEY) {
    user = { id: "subuser", username: "subuser", isAdmin: false, isBanned: false, canDownload: true, role: "user", registered: new Date().toISOString() };
  } else {
    const users = load(F.users, []);
    const byKey = users.find(u => u.loginKey && u.loginKey === key);
    if (byKey && !byKey.isBanned) {
      if (byKey.expiresAt && new Date(byKey.expiresAt) < new Date()) {
        return res.status(403).json({ error: "Key expired" });
      }
      user = byKey;
    }
  }

  if (!user) {
    noteFail(ip);
    audit("login_fail", "unknown", { ip });
    return res.status(401).json({ error: "Invalid key" });
  }

  failMap.delete(ip);
  const users = load(F.users, []);
  const idx = users.findIndex(u => u.id === user.id);
  if (idx >= 0) {
    user = { ...users[idx], ...user, isAdmin: user.isAdmin, username: user.username };
    if (user.id === "subuser" || user.isAdmin) user.canDownload = true;
    users[idx] = user;
  } else users.push(user);
  save(F.users, users);

  req.session.user = {
    id: user.id,
    username: user.username,
    isAdmin: !!user.isAdmin,
    canDownload: !!user.canDownload,
    role: user.role || (user.isAdmin ? "admin" : "user")
  };

  const sess = load(F.sessions, {});
  sess[req.sessionID] = { userId: user.id, username: user.username, ip, at: new Date().toISOString() };
  save(F.sessions, sess);

  let location = "Local";
  try {
    if (ip && ip !== "127.0.0.1" && ip !== "::1") {
      const gr = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,regionName`);
      const gd = await gr.json();
      if (gd.status === "success") location = [gd.city, gd.regionName, gd.country].filter(Boolean).join(", ");
    }
  } catch {}
  const logs = load(F.iplogs, []);
  logs.unshift({ id: uuid(), ip, location, userId: user.id, username: user.username, at: new Date().toISOString() });
  if (logs.length > 500) logs.length = 500;
  save(F.iplogs, logs);
  audit("login", user.username, { ip });
  if (user.isAdmin) webhook(`Admin login: **${user.username}** from \`${ip}\``);

  res.json({ ok: true, user: req.session.user, csrf: req.session.csrfToken });
});

app.post("/auth/logout", (req, res) => {
  const sess = load(F.sessions, {});
  delete sess[req.sessionID];
  save(F.sessions, sess);
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "not logged in" });
  const db = load(F.users, []).find(u => u.id === req.session.user.id) || req.session.user;
  const settings = load(F.settings, {});
  res.json({
    id: db.id, username: db.username, isAdmin: !!db.isAdmin, isBanned: !!db.isBanned,
    canDownload: !!db.canDownload, role: db.role || (db.isAdmin ? "admin" : "user"),
    registered: db.registered, expiresAt: db.expiresAt || null,
    logo: settings.logo || null, csrf: req.session.csrfToken
  });
});
app.get("/api/settings", (req, res) => {
  const s = load(F.settings, {});
  res.json({ maintenance: !!s.maintenance, maintenanceUntil: s.maintenanceUntil || null, logo: s.logo || null, quickLinks: s.quickLinks || [], newsTicker: s.newsTicker || [] });
});

// Chat
app.get("/api/chat", requireAuth, (req, res) => res.json(load(F.chat, []).slice(-100)));
app.post("/api/chat", requireAuth, (req, res) => {
  const content = (req.body.content || "").trim().slice(0, 500);
  if (!content) return res.status(400).json({ error: "empty" });
  const msgs = load(F.chat, []);
  msgs.push({ id: uuid(), content, authorId: req.session.user.id, authorName: req.session.user.username, isAdmin: !!req.session.user.isAdmin, role: req.session.user.role, at: new Date().toISOString() });
  if (msgs.length > 300) msgs.splice(0, msgs.length - 300);
  save(F.chat, msgs);
  res.json(msgs[msgs.length - 1]);
});

// Announcements
app.get("/api/announcements", requireAuth, (req, res) => {
  const list = load(F.announcements, []);
  list.sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || new Date(b.at) - new Date(a.at));
  res.json(list);
});
app.post("/api/announcements", requireAuth, requireAdmin, (req, res) => {
  const { title, body, pinned } = req.body;
  if (!title || !body) return res.status(400).json({ error: "missing" });
  const list = load(F.announcements, []);
  list.unshift({ id: uuid(), title: String(title).slice(0, 120), body: String(body).slice(0, 2000), pinned: !!pinned, authorName: req.session.user.username, at: new Date().toISOString() });
  save(F.announcements, list);
  res.json(list[0]);
});
app.delete("/api/announcements/:id", requireAuth, requireAdmin, (req, res) => {
  save(F.announcements, load(F.announcements, []).filter(a => a.id !== req.params.id));
  res.json({ ok: true });
});

// Tickets
app.get("/api/tickets", requireAuth, (req, res) => {
  const all = load(F.tickets, []);
  res.json(req.session.user.isAdmin ? all : all.filter(t => t.userId === req.session.user.id));
});
app.post("/api/tickets", requireAuth, (req, res) => {
  const { subject, body, priority } = req.body;
  if (!subject || !body) return res.status(400).json({ error: "missing" });
  const list = load(F.tickets, []);
  list.unshift({ id: uuid(), subject: String(subject).slice(0, 100), body: String(body).slice(0, 2000), status: "open", priority: ["low","normal","high"].includes(priority) ? priority : "normal", replies: [], userId: req.session.user.id, username: req.session.user.username, at: new Date().toISOString() });
  save(F.tickets, list);
  res.json(list[0]);
});
app.post("/api/tickets/:id/reply", requireAuth, (req, res) => {
  const body = (req.body.body || "").trim();
  if (!body) return res.status(400).json({ error: "empty" });
  const list = load(F.tickets, []);
  const t = list.find(x => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "not found" });
  if (!req.session.user.isAdmin && t.userId !== req.session.user.id) return res.status(403).json({ error: "forbidden" });
  if (!t.replies) t.replies = [];
  t.replies.push({ id: uuid(), body: body.slice(0, 2000), authorId: req.session.user.id, authorName: req.session.user.username, isAdmin: !!req.session.user.isAdmin, at: new Date().toISOString() });
  save(F.tickets, list);
  res.json(t);
});
app.patch("/api/tickets/:id", requireAuth, requireAdmin, (req, res) => {
  const list = load(F.tickets, []);
  const t = list.find(x => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "not found" });
  if (req.body.status) t.status = req.body.status;
  save(F.tickets, list);
  res.json(t);
});

// Giveaways
app.get("/api/giveaways", requireAuth, (req, res) => res.json(load(F.giveaways, [])));
app.post("/api/giveaways", requireAuth, requireAdmin, (req, res) => {
  const { prize, endsAt, onePerIp } = req.body;
  if (!prize || !endsAt) return res.status(400).json({ error: "missing" });
  const list = load(F.giveaways, []);
  list.unshift({ id: uuid(), prize, endsAt, isActive: true, onePerIp: !!onePerIp, entries: [], winnerName: null, createdAt: new Date().toISOString() });
  save(F.giveaways, list);
  res.json(list[0]);
});
app.post("/api/giveaways/:id/join", requireAuth, (req, res) => {
  const list = load(F.giveaways, []);
  const g = list.find(x => x.id === req.params.id);
  if (!g?.isActive) return res.status(400).json({ error: "not active" });
  const ip = clientIp(req);
  if (g.entries.find(e => e.userId === req.session.user.id)) return res.status(400).json({ error: "already joined" });
  if (g.onePerIp && g.entries.find(e => e.ip === ip)) return res.status(400).json({ error: "IP already entered" });
  g.entries.push({ userId: req.session.user.id, username: req.session.user.username, ip, at: new Date().toISOString() });
  save(F.giveaways, list);
  res.json({ ok: true, count: g.entries.length });
});
app.post("/api/giveaways/:id/draw", requireAuth, requireAdmin, (req, res) => {
  const list = load(F.giveaways, []);
  const g = list.find(x => x.id === req.params.id);
  if (!g?.entries?.length) return res.status(400).json({ error: "no entries" });
  const w = g.entries[Math.floor(Math.random() * g.entries.length)];
  g.winnerName = w.username; g.isActive = false;
  save(F.giveaways, list);
  res.json(g);
});

// Files
app.get("/api/files/:folder", requireAuth, (req, res) => {
  const folder = req.params.folder.toLowerCase();
  if (!FILE_FOLDERS.includes(folder)) return res.status(400).json({ error: "invalid" });
  const dbUser = load(F.users, []).find(u => u.id === req.session.user.id) || req.session.user;
  const unlocked = !!(dbUser.isAdmin || dbUser.canDownload);
  const dir = path.join(__dirname, "files", folder);
  let files = [];
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    files = fs.readdirSync(dir).filter(f => !f.startsWith(".")).sort((a,b)=>a.localeCompare(b)).map(f => {
      const fp = path.join(dir, f);
      const st = fs.statSync(fp);
      const h = fileHash(fp);
      const vm = f.match(/[_\-.]v?(\d+\.\d+(?:\.\d+)?)/i);
      return { name: f, size: st.size, unlocked, version: vm ? vm[1] : null, md5: h?.md5 || null };
    });
  } catch {}
  res.json({ folder, unlocked, files });
});
app.get("/api/files-search", requireAuth, (req, res) => {
  const q = String(req.query.q || "").toLowerCase().trim();
  if (!q) return res.json([]);
  const dbUser = load(F.users, []).find(u => u.id === req.session.user.id) || req.session.user;
  const unlocked = !!(dbUser.isAdmin || dbUser.canDownload);
  const out = [];
  for (const folder of FILE_FOLDERS) {
    try {
      fs.readdirSync(path.join(__dirname, "files", folder)).filter(f => !f.startsWith(".") && f.toLowerCase().includes(q)).forEach(f => out.push({ folder, name: f, unlocked }));
    } catch {}
  }
  res.json(out.sort((a,b)=>a.name.localeCompare(b.name)).slice(0, 50));
});
app.get("/api/files/:folder/:file", requireAuth, (req, res) => {
  const folder = req.params.folder.toLowerCase();
  if (!FILE_FOLDERS.includes(folder)) return res.status(400).send("invalid");
  const dbUser = load(F.users, []).find(u => u.id === req.session.user.id) || req.session.user;
  if (!dbUser.isAdmin && !dbUser.canDownload) return res.status(403).send("Locked");
  const fp = path.join(__dirname, "files", folder, path.basename(req.params.file));
  if (!fs.existsSync(fp)) return res.status(404).send("Not found");
  const hist = load(F.downloads, []);
  hist.unshift({ id: uuid(), userId: req.session.user.id, username: req.session.user.username, folder, file: path.basename(req.params.file), ip: clientIp(req), at: new Date().toISOString() });
  if (hist.length > 2000) hist.length = 2000;
  save(F.downloads, hist);
  res.download(fp);
});

app.get("/api/changelog", requireAuth, (req, res) => res.json(load(F.changelog, [])));
app.post("/api/changelog", requireAuth, requireAdmin, (req, res) => {
  const { folder, file, notes, version } = req.body;
  if (!folder || !notes) return res.status(400).json({ error: "missing" });
  const list = load(F.changelog, []);
  list.unshift({ id: uuid(), folder, file: file || "", notes, version: version || "", author: req.session.user.username, at: new Date().toISOString() });
  save(F.changelog, list);
  res.json(list[0]);
});

app.post("/api/redeem", requireAuth, (req, res) => {
  const code = String(req.body.code || "").trim();
  const list = load(F.codes, []);
  const c = list.find(x => x.code === code && !x.usedBy);
  if (!c) return res.status(400).json({ error: "Invalid or used code" });
  c.usedBy = req.session.user.id; c.usedAt = new Date().toISOString();
  save(F.codes, list);
  const users = load(F.users, []);
  const u = users.find(x => x.id === req.session.user.id);
  if (u) {
    u.canDownload = true;
    const exp = new Date(); exp.setDate(exp.getDate() + (c.days || 30));
    u.expiresAt = exp.toISOString();
    u.role = "vip";
    save(F.users, users);
  }
  res.json({ ok: true, days: c.days });
});

app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => res.json(load(F.users, [])));
app.patch("/api/admin/users/:id", requireAuth, requireAdmin, (req, res) => {
  const users = load(F.users, []);
  const u = users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: "not found" });
  if (typeof req.body.isBanned === "boolean") u.isBanned = req.body.isBanned;
  if (typeof req.body.canDownload === "boolean") u.canDownload = req.body.canDownload;
  if (typeof req.body.staffNote === "string") u.staffNote = req.body.staffNote.slice(0, 500);
  if (typeof req.body.role === "string") u.role = req.body.role;
  save(F.users, users);
  res.json(u);
});
app.get("/api/admin/blacklist", requireAuth, requireAdmin, (req, res) => res.json(load(F.blacklist, [])));
app.post("/api/admin/blacklist", requireAuth, requireAdmin, (req, res) => {
  const { target, type, reason } = req.body;
  if (!target || !type) return res.status(400).json({ error: "missing" });
  const list = load(F.blacklist, []);
  list.unshift({ id: uuid(), target, type, reason: reason || "", at: new Date().toISOString() });
  save(F.blacklist, list);
  res.json({ ok: true });
});
app.delete("/api/admin/blacklist/:id", requireAuth, requireAdmin, (req, res) => {
  save(F.blacklist, load(F.blacklist, []).filter(b => b.id !== req.params.id));
  res.json({ ok: true });
});
app.get("/api/admin/iplogs", requireAuth, requireAdmin, (req, res) => res.json(load(F.iplogs, []).slice(0, 200)));
app.get("/api/admin/downloads", requireAuth, requireAdmin, (req, res) => res.json(load(F.downloads, []).slice(0, 200)));
app.get("/api/admin/audit", requireAuth, requireAdmin, (req, res) => res.json(load(F.audit, []).slice(0, 200)));
app.get("/api/admin/sessions", requireAuth, requireAdmin, (req, res) => {
  const sess = load(F.sessions, {});
  res.json(Object.entries(sess).map(([id, v]) => ({ id, ...v })));
});
app.delete("/api/admin/sessions/:id", requireAuth, requireAdmin, (req, res) => {
  const sess = load(F.sessions, {});
  delete sess[req.params.id];
  save(F.sessions, sess);
  res.json({ ok: true });
});
app.get("/api/admin/codes", requireAuth, requireAdmin, (req, res) => res.json(load(F.codes, [])));
app.post("/api/admin/codes", requireAuth, requireAdmin, (req, res) => {
  const days = Number(req.body.days) || 30;
  const code = crypto.randomBytes(12).toString("base64url");
  const list = load(F.codes, []);
  list.unshift({ id: uuid(), code, days, usedBy: null, createdAt: new Date().toISOString() });
  save(F.codes, list);
  res.json(list[0]);
});
app.post("/api/admin/maintenance", requireAuth, requireAdmin, (req, res) => {
  const s = load(F.settings, {});
  s.maintenance = !!req.body.enabled;
  s.maintenanceUntil = req.body.until || null;
  save(F.settings, s);
  res.json(s);
});
app.post("/api/admin/settings", requireAuth, requireAdmin, (req, res) => {
  const s = load(F.settings, {});
  if (Array.isArray(req.body.quickLinks)) s.quickLinks = req.body.quickLinks.slice(0, 8);
  if (Array.isArray(req.body.newsTicker)) s.newsTicker = req.body.newsTicker.slice(0, 10).map(String);
  save(F.settings, s);
  res.json(s);
});
app.get("/api/admin/backup", requireAuth, requireAdmin, (req, res) => {
  const out = {};
  for (const [k, file] of Object.entries(F)) out[k] = load(file, []);
  res.setHeader("Content-Disposition", "attachment; filename=opsec-backup.json");
  res.json(out);
});

app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal error" });
});

app.listen(PORT, () => {
  console.log(`\n  OPSECSTUDIOS → http://localhost:${PORT}`);
  console.log(`  Subuser key: ${SUBUSER_KEY.slice(0, 8)}...`);
  console.log(`  Admin key:   ${ADMIN_KEY}\n`);
});

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const DB_DIR = path.join(__dirname, "data");
fs.mkdirSync(DB_DIR, { recursive: true });

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("Set SESSION_SECRET to a random value of at least 32 characters.");
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
  throw new Error("Set ADMIN_EMAIL and ADMIN_PASSWORD before starting.");
}

const db = new Database(path.join(DB_DIR, "portal.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS instagram_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    ig_user_id TEXT,
    ig_username TEXT,
    access_token TEXT NOT NULL,
    token_expires_at TEXT,
    connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const adminEmail = process.env.ADMIN_EMAIL.trim().toLowerCase();
const existingAdmin = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, 1)").run(adminEmail, hash);
}

app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: null
    }
  }
}));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DB_DIR }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: "draft-7", legacyHeaders: false });
const oauthLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false });

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}
function csrfToken(req) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString("hex");
  return req.session.csrf;
}
function checkCsrf(req, res, next) {
  const supplied = req.body.csrf || req.query.csrf;
  if (!supplied || !req.session.csrf || !crypto.timingSafeEqual(
    Buffer.from(String(supplied)), Buffer.from(String(req.session.csrf))
  )) return res.status(403).send(page("Request expired", `<p>Refresh the page and try again.</p>`));
  next();
}
function page(title, body, req) {
  const user = req && req.session.user;
  const nav = user
    ? `<nav><span>Private Portal</span><a href="/dashboard">Dashboard</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="${csrfToken(req)}"><button class="link">Log out</button></form></nav>`
    : `<nav><span>Private Portal</span><a href="/">Home</a><a href="/login">Log in</a><a href="/register">Create account</a></nav>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/style.css"></head><body>${nav}<main><h1>${escapeHtml(title)}</h1>${body}</main><footer>Use only accounts you own or are authorized to connect. Instagram passwords are never requested or stored.</footer></body></html>`;
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.isAdmin) return res.status(403).send(page("Not authorized", "<p>Administrator access is required.</p>", req));
  next();
}
function metaConfigured() {
  return Boolean(process.env.META_APP_ID && process.env.META_APP_SECRET && process.env.META_REDIRECT_URI);
}
function safeReturn(res, message) {
  return res.redirect("/dashboard?notice=" + encodeURIComponent(message));
}

app.get("/style.css", (req, res) => res.type("text/css").send(fs.readFileSync(path.join(__dirname, "public/style.css"), "utf8")));
app.get("/", (req, res) => res.send(page("Your private portal", `
  <p>A private member area with an optional, official Instagram connection.</p>
  <div class="actions"><a class="button" href="/register">Create an account</a><a class="button secondary" href="/login">Log in</a></div>
  <p class="muted">Instagram connection is available only to eligible Instagram professional accounts through Meta's authorization flow.</p>
`, req)));

app.get("/register", (req, res) => res.send(page("Create account", `
  <form method="post" action="/register">
    <input type="hidden" name="csrf" value="${csrfToken(req)}">
    <label>Email<input name="email" type="email" maxlength="254" required autocomplete="email"></label>
    <label>Password<input name="password" type="password" minlength="12" required autocomplete="new-password"><small>Use at least 12 characters. Choose a unique password.</small></label>
    <button>Create account</button>
  </form>
  <p>Already registered? <a href="/login">Log in</a>.</p>
`, req)));

app.post("/register", authLimiter, checkCsrf, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12 || password.length > 200) {
    return res.status(400).send(page("Check your details", "<p>Enter a valid email and a password of at least 12 characters.</p>", req));
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").run(email, hash);
    req.session.regenerate(err => {
      if (err) return res.status(500).send("Could not start session.");
      req.session.user = { id: Number(result.lastInsertRowid), email, isAdmin: false };
      res.redirect("/dashboard");
    });
  } catch {
    res.status(409).send(page("Account not created", "<p>An account with that email may already exist.</p><p><a href='/login'>Try logging in</a>.</p>", req));
  }
});

app.get("/login", (req, res) => res.send(page("Log in", `
  <form method="post" action="/login">
    <input type="hidden" name="csrf" value="${csrfToken(req)}">
    <label>Email<input name="email" type="email" required autocomplete="username"></label>
    <label>Password<input name="password" type="password" required autocomplete="current-password"></label>
    <button>Log in</button>
  </form>
  <p>New here? <a href="/register">Create an account</a>.</p>
`, req)));

app.post("/login", authLimiter, checkCsrf, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  const valid = user && await bcrypt.compare(String(req.body.password || ""), user.password_hash);
  if (!valid) return res.status(401).send(page("Login failed", "<p>Email or password is incorrect.</p><p><a href='/login'>Try again</a>.</p>", req));
  req.session.regenerate(err => {
    if (err) return res.status(500).send("Could not start session.");
    req.session.user = { id: user.id, email: user.email, isAdmin: Boolean(user.is_admin) };
    res.redirect("/dashboard");
  });
});

app.post("/logout", checkCsrf, (req, res) => req.session.destroy(() => res.redirect("/")));

app.get("/dashboard", requireAuth, (req, res) => {
  const connection = db.prepare("SELECT ig_username, connected_at FROM instagram_connections WHERE user_id = ?").get(req.session.user.id);
  const notice = req.query.notice ? `<p class="notice">${escapeHtml(req.query.notice)}</p>` : "";
  const ig = connection
    ? `<p><strong>Connected Instagram:</strong> @${escapeHtml(connection.ig_username || "connected")}</p><form method="post" action="/instagram/disconnect"><input type="hidden" name="csrf" value="${csrfToken(req)}"><button class="secondary">Disconnect Instagram</button></form>`
    : `<p>No Instagram account connected.</p><a class="button" href="/auth/instagram">Connect Instagram</a>`;
  const admin = req.session.user.isAdmin ? `<p><a href="/admin">Open administrator dashboard</a></p>` : "";
  const configWarning = !metaConfigured() ? `<p class="warning">Meta app settings are not configured yet. Add the Meta values to your .env file to enable Instagram connection.</p>` : "";
  res.send(page("Dashboard", `${notice}<p>Signed in as <strong>${escapeHtml(req.session.user.email)}</strong>.</p>${configWarning}<section class="panel"><h2>Instagram connection</h2>${ig}<p class="muted">You will be redirected to Instagram/Meta to approve access. This site never asks for your Instagram password.</p></section>${admin}`, req));
});

app.get("/admin", requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.email, u.created_at, i.ig_username, i.connected_at
    FROM users u LEFT JOIN instagram_connections i ON i.user_id = u.id
    ORDER BY u.created_at DESC
  `).all();
  const rows = users.map(u => `<tr><td>${escapeHtml(u.email)}</td><td>${u.is_admin ? "Admin" : "Member"}</td><td>${u.ig_username ? "@" + escapeHtml(u.ig_username) : "Not connected"}</td><td>${escapeHtml(u.created_at)}</td></tr>`).join("");
  res.send(page("Administrator dashboard", `<p>Member directory. Passwords are never displayed; only salted password hashes are stored.</p><div class="table-wrap"><table><thead><tr><th>Email</th><th>Role</th><th>Instagram</th><th>Joined</th></tr></thead><tbody>${rows || "<tr><td colspan='4'>No members yet.</td></tr>"}</tbody></table></div>`, req));
});

app.get("/auth/instagram", requireAuth, oauthLimiter, (req, res) => {
  if (!metaConfigured()) return safeReturn(res, "Instagram connection is not configured yet.");
  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: process.env.META_APP_ID,
    redirect_uri: process.env.META_REDIRECT_URI,
    response_type: "code",
    scope: "instagram_business_basic",
    state
  });
  res.redirect(`https://www.instagram.com/oauth/authorize?${params.toString()}`);
});

app.get("/auth/instagram/callback", requireAuth, oauthLimiter, async (req, res) => {
  if (req.query.error) return safeReturn(res, "Instagram authorization was cancelled or denied.");
  const code = String(req.query.code || "");
  const state = String(req.query.state || "");
  if (!code || !req.session.oauthState || state !== req.session.oauthState) return res.status(400).send("Invalid authorization response.");
  delete req.session.oauthState;

  try {
    const form = new URLSearchParams({
      client_id: process.env.META_APP_ID,
      client_secret: process.env.META_APP_SECRET,
      grant_type: "authorization_code",
      redirect_uri: process.env.META_REDIRECT_URI,
      code
    });
    const tokenResponse = await fetch("https://api.instagram.com/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) throw new Error("Instagram token exchange failed.");

    const apiVersion = process.env.META_API_VERSION || "v27.0";
    const profileUrl = new URL(`https://graph.instagram.com/${apiVersion}/me`);
    profileUrl.searchParams.set("fields", "user_id,username");
    profileUrl.searchParams.set("access_token", tokenData.access_token);
    const profileResponse = await fetch(profileUrl);
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.username) throw new Error("Could not retrieve Instagram profile.");

    // Exchange for a long-lived token. Store tokens server-side only; never expose them in HTML.
    const longUrl = new URL(`https://graph.instagram.com/${apiVersion}/access_token`);
    longUrl.searchParams.set("grant_type", "ig_exchange_token");
    longUrl.searchParams.set("client_secret", process.env.META_APP_SECRET);
    longUrl.searchParams.set("access_token", tokenData.access_token);
    const longResponse = await fetch(longUrl);
    const longData = await longResponse.json();
    const accessToken = longResponse.ok && longData.access_token ? longData.access_token : tokenData.access_token;
    const expiresAt = longData.expires_in ? new Date(Date.now() + Number(longData.expires_in) * 1000).toISOString() : null;

    db.prepare(`
      INSERT INTO instagram_connections (user_id, ig_user_id, ig_username, access_token, token_expires_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        ig_user_id=excluded.ig_user_id, ig_username=excluded.ig_username,
        access_token=excluded.access_token, token_expires_at=excluded.token_expires_at,
        connected_at=CURRENT_TIMESTAMP
    `).run(req.session.user.id, String(profile.user_id || ""), profile.username, accessToken, expiresAt);
    safeReturn(res, `Connected Instagram account @${profile.username}.`);
  } catch (err) {
    console.error("Instagram OAuth error:", err.message);
    safeReturn(res, "Instagram connection failed. Check your Meta app configuration and try again.");
  }
});

app.post("/instagram/disconnect", requireAuth, checkCsrf, (req, res) => {
  db.prepare("DELETE FROM instagram_connections WHERE user_id = ?").run(req.session.user.id);
  safeReturn(res, "Instagram account disconnected.");
});

app.use((req, res) => res.status(404).send(page("Page not found", "<p>The page you requested does not exist.</p>", req)));

app.listen(PORT, () => {
  console.log(`Private portal running at ${BASE_URL}`);
});

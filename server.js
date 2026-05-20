const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

// Use pure-JS asm.js build — no WebAssembly, works on Vercel serverless
const initSqlJs = require("sql.js/dist/sql-asm.js");

const app = express();
const PORT = process.env.PORT || 3002;
const DB_FILE = process.env.VERCEL
  ? "/tmp/wmh_barber.db"
  : path.join(__dirname, "wmh_barber.db");

// ── Database ─────────────────────────────────────────────────────
let db;
let dbReady = false;
let dbInitPromise = null;

function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_FILE, Buffer.from(data));
}

function loadDb(SQL) {
  if (fs.existsSync(DB_FILE)) {
    return new SQL.Database(fs.readFileSync(DB_FILE));
  }
  return new SQL.Database();
}

async function initDb() {
  const SQL = await initSqlJs();
  db = loadDb(SQL);
  db.run(`
    CREATE TABLE IF NOT EXISTS bookings (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT NOT NULL,
      phone      TEXT NOT NULL,
      service    TEXT NOT NULL,
      price      INTEGER NOT NULL DEFAULT 0,
      duration   TEXT NOT NULL DEFAULT '',
      date       TEXT NOT NULL,
      time       TEXT NOT NULL,
      barber     TEXT NOT NULL DEFAULT 'Any available',
      status     TEXT NOT NULL DEFAULT 'pending',
      notes      TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS admin_users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `);
  saveDb();
  const adminRows = db.exec("SELECT id FROM admin_users LIMIT 1");
  if (!adminRows.length || !adminRows[0].values.length) {
    const hash = bcrypt.hashSync("admin123", 10);
    db.run("INSERT INTO admin_users (username, password) VALUES (?, ?)", ["admin", hash]);
    saveDb();
  }
  dbReady = true;
}

// Lazy DB init — safe for serverless cold starts
function ensureDb(req, res, next) {
  if (dbReady) return next();
  if (!dbInitPromise) dbInitPromise = initDb();
  dbInitPromise.then(next).catch(err => {
    console.error("DB init error:", err);
    res.status(500).json({ error: "Database init failed" });
  });
}

// Helpers
function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    const obj = {};
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    cols.forEach((c, i) => { obj[c] = vals[i]; });
    rows.push(obj);
  }
  stmt.free();
  return rows;
}
function dbGet(sql, params = []) { return dbAll(sql, params)[0] || null; }
function dbRun(sql, params = []) {
  db.run(sql, params);
  const lastId = db.exec("SELECT last_insert_rowid() as id")[0]?.values[0]?.[0];
  saveDb();
  return { lastInsertRowid: lastId };
}

// ── Middleware ───────────────────────────────────────────────────
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: "wmh-barber-secret-2024",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: !!process.env.VERCEL, maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api", ensureDb);

// ── Auth ─────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session && req.session.adminId) return next();
  res.status(401).json({ error: "Unauthorized" });
}

// ── Public API ───────────────────────────────────────────────────
app.post("/api/bookings", (req, res) => {
  const { name, phone, service, price, duration, date, time, barber } = req.body;
  if (!name || !phone || !service || !date || !time)
    return res.status(400).json({ error: "Missing required fields" });
  const result = dbRun(
    "INSERT INTO bookings (name, phone, service, price, duration, date, time, barber) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [name.trim(), phone.trim(), service, price || 0, duration || "", date, time, barber || "Any available"]
  );
  res.json({ success: true, bookingId: result.lastInsertRowid });
});

app.get("/api/booked-slots", (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: "date required" });
  const rows = dbAll("SELECT time FROM bookings WHERE date = ? AND status != 'cancelled'", [date]);
  res.json({ bookedSlots: rows.map(r => r.time) });
});

// ── Admin API ────────────────────────────────────────────────────
app.post("/api/admin/login", ensureDb, (req, res) => {
  const { username, password } = req.body;
  const user = dbGet("SELECT * FROM admin_users WHERE username = ?", [username]);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Invalid credentials" });
  req.session.adminId = user.id;
  res.json({ success: true });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get("/api/admin/bookings", requireAdmin, (req, res) => {
  const { status, date, search } = req.query;
  let sql = "SELECT * FROM bookings WHERE 1=1";
  const params = [];
  if (status && status !== "all") { sql += " AND status = ?"; params.push(status); }
  if (date) { sql += " AND date = ?"; params.push(date); }
  if (search) {
    sql += " AND (name LIKE ? OR phone LIKE ? OR service LIKE ?)";
    const q = `%${search}%`;
    params.push(q, q, q);
  }
  sql += " ORDER BY date DESC, time DESC";
  res.json({ bookings: dbAll(sql, params) });
});

app.patch("/api/admin/bookings/:id/status", requireAdmin, (req, res) => {
  const { status } = req.body;
  if (!["pending", "confirmed", "cancelled", "completed"].includes(status))
    return res.status(400).json({ error: "Invalid status" });
  dbRun("UPDATE bookings SET status = ? WHERE id = ?", [status, req.params.id]);
  res.json({ success: true });
});

app.patch("/api/admin/bookings/:id/notes", requireAdmin, (req, res) => {
  dbRun("UPDATE bookings SET notes = ? WHERE id = ?", [req.body.notes || "", req.params.id]);
  res.json({ success: true });
});

app.delete("/api/admin/bookings/:id", requireAdmin, (req, res) => {
  dbRun("DELETE FROM bookings WHERE id = ?", [req.params.id]);
  res.json({ success: true });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const total     = dbGet("SELECT COUNT(*) as n FROM bookings")?.n || 0;
  const pending   = dbGet("SELECT COUNT(*) as n FROM bookings WHERE status='pending'")?.n || 0;
  const confirmed = dbGet("SELECT COUNT(*) as n FROM bookings WHERE status='confirmed'")?.n || 0;
  const todayStr  = new Date().toISOString().slice(0, 10);
  const today     = dbGet("SELECT COUNT(*) as n FROM bookings WHERE date=?", [todayStr])?.n || 0;
  const revenue   = dbGet("SELECT COALESCE(SUM(price),0) as n FROM bookings WHERE status != 'cancelled'")?.n || 0;
  res.json({ total, pending, confirmed, today, revenue });
});

app.get("/api/admin/session", (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.adminId) });
});

// ── Pages ────────────────────────────────────────────────────────
app.get("/admin", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "admin.html"))
);
app.get("*", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

// ── Start ────────────────────────────────────────────────────────
if (require.main === module) {
  initDb().then(() => {
    app.listen(PORT, () => {
      console.log(`\n  WMH Barber running!`);
      console.log(`  http://localhost:${PORT}\n`);
    });
  }).catch(err => { console.error(err); process.exit(1); });
} else {
  // Vercel: export app, DB inits lazily on first request
  module.exports = app;
}

import express from "express";
import fs from "fs/promises";
import path from "path";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Server as IOServer } from "socket.io";
import http from "http";
import nodemailer from "nodemailer";
import QRCode from "qrcode";
import csurf from "csurf";
import { v4 as uuidv4 } from "uuid";
import { MongoClient } from "mongodb";
import cors from "cors";


dotenv.config();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.resolve("./data.json");
const PUBLIC_DIR = path.resolve("./"); // Serve current folder

// ---------- Location Config (edit these) ----------
// Set your restaurant latitude/longitude here. Radius is set to 10 meters.
// Environment variables (RESTAURANT_LAT/RESTAURANT_LNG/RESTAURANT_RADIUS_METERS) still override if present.
const CONFIG_LOCATION = {
  lat: Number(process.env.RESTAURANT_LAT) || 14.478144241010149,
  lng: Number(process.env.RESTAURANT_LNG) || 75.88522999510667,
  radiusMeters: Number(process.env.RESTAURANT_RADIUS_METERS || process.env.PROXIMITY_RADIUS_METERS) || 10
};

// Log loaded location config at startup
console.log("[Config] Restaurant Location:", CONFIG_LOCATION);
app.use(cors({
    origin: "*",
    methods: "GET,POST",
    credentials: true
}));

const app = express();
app.use(cors({
  origin: "*",
  methods: ["GET", "POST"],
  credentials: true
}));
const server = http.createServer(app);
const io = new IOServer(server, { cors: { origin: true, credentials: true } });

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com"
      ],
      "script-src-elem": [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com"
      ],
      // Allow inline event handlers like onclick for existing HTML pages
      "script-src-attr": ["'unsafe-inline'"],
      "style-src": [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com"
      ],
      "img-src": ["'self'", "data:"],
      "connect-src": ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:"],
      "frame-ancestors": ["'self'"]
    }
  }
}));
app.use(express.json());
app.use(cookieParser());
// Protect selected admin pages while keeping the rest of the site public
const PROTECTED_PAGES = new Set([
  "/admin.html",
  "/analytics.html",
  "/bill.html",
  "/categories.html",
  "/menumng.html",
  "/orders.html",
  "/qrgenerator.html",
  "/settings.html"
]);

function ensureAdminPage(req, res, next) {
  try {
    const token = req.cookies.session;
    if (!token) throw new Error("no token");
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.username) throw new Error("invalid token");
    return next();
  } catch (e) {
    return res.redirect("/login.html");
  }
}

// Intercept requests to protected HTML pages and verify admin
app.get(Array.from(PROTECTED_PAGES), ensureAdminPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, req.path));
});

// Serve other static assets as usual
app.use(express.static(PUBLIC_DIR));
// Protect admin pages
app.use("/secure", auth, express.static(path.join(PUBLIC_DIR, "secure")));
app.use("/secure", (req, res) => {
  res.redirect("/login.html");
});

const csrfProtection = csurf({ cookie: true });

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { ok: false, message: "Too many requests" }
});
app.use("/api/orders/create", limiter);

// ---------- Utility ----------
// ---------- Storage Layer (MongoDB with file fallback) ----------
let mongoClient = null;
let mongoDb = null;

async function connectMongoIfConfigured() {
  const uri = process.env.MONGODB_URI;
  const dbName = process.env.MONGODB_DB || "qrrp";
  if (!uri) return null;
  if (mongoDb) return mongoDb;
  mongoClient = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
  await mongoClient.connect();
  mongoDb = mongoClient.db(dbName);
  return mongoDb;
}

async function readData() {
  try {
    const raw = await fs.readFile(DATA_FILE, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') {  // Handle if file not exist
      const defaultData = {
        admin: { username: process.env.ADMIN_USERNAME || 'admin' },
        tables: [],
        orders: []
      };
      await writeData(defaultData);  // Create file with default
      return defaultData;
    }
    throw err;  // Other errors
  }
}
async function writeData(data) {
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}
function dist(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = lat1 * Math.PI/180, φ2 = lat2 * Math.PI/180;
  const Δφ = (lat2 - lat1) * Math.PI/180, Δλ = (lon2 - lon1) * Math.PI/180;
  const a = Math.sin(Δφ/2)**2 + Math.cos(φ1)*Math.cos(φ2)*Math.sin(Δλ/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}
const JWT_SECRET = process.env.JWT_SECRET || "secret";
function signQr(payload, exp = "10m") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: exp });
}
function verifyQr(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// ---------- Mail ----------
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
async function sendMail(order) {
  if (!process.env.NOTIFY_EMAIL) return;
  await mailer.sendMail({
    from: process.env.SMTP_USER,
    to: process.env.NOTIFY_EMAIL,
    subject: `New order #${order.id} - Table ${order.tableId}`,
    text: order.items.map(i => `${i.name} x${i.qty}`).join("\n")
  }).catch(console.warn);
}

// ---------- Auth ----------
function auth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ ok: false });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ ok: false });
  }
}

// ---------- Init ----------
async function init() {
  // Try Mongo connect
  try {
    await connectMongoIfConfigured();
  } catch (e) {
    console.warn("MongoDB connection failed, using file storage:", e.message);
  }

  if (mongoDb) {
    // Ensure admin exists and migrate from file once
    const adminCol = mongoDb.collection("admin");
    const tablesCol = mongoDb.collection("tables");
    const ordersCol = mongoDb.collection("orders");

    let adminDoc = await adminCol.findOne({ _id: "admin" });
    if (!adminDoc) {
      // Try migrate from file, else create default
      let d = null;
      try { d = await readData(); } catch {}
      const username = d?.admin?.username || process.env.ADMIN_USERNAME || 'admin';
      const passwordHash = d?.admin?.passwordHash || bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
      await adminCol.updateOne(
        { _id: "admin" },
        { $set: { username, passwordHash } },
        { upsert: true }
      );
      // migrate tables
      if (Array.isArray(d?.tables)) {
        for (const t of d.tables) {
          const pinHash = t.pinHash || bcrypt.hashSync(t.pinPlain || "1234", 10);
          await tablesCol.updateOne(
            { id: String(t.id) },
            { $set: { id: String(t.id), pinHash } },
            { upsert: true }
          );
        }
      }
      // migrate orders
      if (Array.isArray(d?.orders)) {
        if ((await ordersCol.estimatedDocumentCount()) === 0) {
          await ordersCol.insertMany(d.orders.map(o => ({ ...o, _id: o.id })));
        }
      }
    }
  } else {
    // File storage initialization
    const d = await readData();
    if (!d.admin) {  // Create admin if missing
      d.admin = { username: process.env.ADMIN_USERNAME || 'admin' };
    }
    if (!d.admin.passwordHash) {
      d.admin.passwordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
    }
    for (let t of d.tables) {
      if (!t.pinHash) {
        t.pinHash = bcrypt.hashSync(t.pinPlain || "1234", 10);
        delete t.pinPlain;  // Remove plain pin for security
      }
    }
    await writeData(d);
  }
}
await init();

// ---------- API ----------
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (mongoDb) {
    const adm = await mongoDb.collection("admin").findOne({ _id: "admin" });
    if (!adm || username !== adm.username) return res.status(401).json({ ok: false, msg: 'Invalid username' });
    if (!bcrypt.compareSync(password, adm.passwordHash))
      return res.status(401).json({ ok: false, msg: 'Invalid password' });
  } else {
    const d = await readData();
    if (username !== d.admin.username) return res.status(401).json({ ok: false, msg: 'Invalid username' });
    if (!bcrypt.compareSync(password, d.admin.passwordHash))
      return res.status(401).json({ ok: false, msg: 'Invalid password' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "8h" });
  res.cookie("session", token, { httpOnly: true, sameSite: "lax", secure: false, path: "/" });
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  try {
    const decoded = jwt.verify(req.cookies.session, JWT_SECRET);
    res.json({ ok: true, user: decoded, sessionExpiry: decoded.exp * 1000 });
  } catch {
    res.status(401).json({ ok: false, msg: "Invalid or expired session" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("session");
  res.json({ ok: true });
});

app.post("/api/admin/generate-qr", auth, async (req, res) => {
  const { tableId } = req.body;
  const token = signQr({ tableId }, "10m");
  console.log("[QR][admin] tableId=", tableId, " token=", token);
  const qrUrl = `${req.protocol}://${req.get("host")}/index.html?token=${encodeURIComponent(token)}`;
  let qrImageData = null;
  try {
    qrImageData = await QRCode.toDataURL(qrUrl, { errorCorrectionLevel: 'L', margin: 0, width: 180 });
  } catch (e) { console.warn("QR generation failed", e.message); }
  res.json({ ok: true, qrUrl, qrImageData, expiresInSeconds: 600 });
});

// Frontend QR generator endpoint used by qrgenerator.html
app.post("/api/qr/generate", auth, async (req, res) => {
  try {
    const table = req.body.table;
    const baseUrl = String(req.body.baseUrl || "").trim();
    if (!table) return res.status(400).json({ ok: false, message: "table required" });
    if (!baseUrl) return res.status(400).json({ ok: false, message: "baseUrl required" });
    const token = signQr({ tableId: String(table) }, "10m");
    console.log("[QR][front] table=", table, " token=", token);
    const url = `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}`;
    let qrImageData = null;
    try {
      qrImageData = await QRCode.toDataURL(url, { errorCorrectionLevel: 'L', margin: 0, width: 180 });
    } catch (e) { console.warn("QR generation failed", e.message); }
    res.json({ ok: true, url, qrImageData, expiresInSeconds: 600 });
  } catch (e) {
    res.status(500).json({ ok: false, message: "QR generation error" });
  }
});

app.post("/api/validate-location", async (req, res) => {
  const { token, lat, lng } = req.body;
  const payload = verifyQr(token);
  if (!payload) {
    console.log("[Location Check] Invalid QR token");
    return res.json({ ok: false, msg: "Invalid QR token" });
  }

  // Admin bypass: if logged-in admin calls this, always allow
  let isAdmin = false;
  try {
    const session = req.cookies.session ? jwt.verify(req.cookies.session, JWT_SECRET) : null;
    if (session) {
      let adminUsername = 'admin';
      if (mongoDb) {
        const adm = await mongoDb.collection("admin").findOne({ _id: "admin" });
        adminUsername = adm?.username || process.env.ADMIN_USERNAME || 'admin';
      } else {
        const d = await readData();
        adminUsername = d.admin?.username || process.env.ADMIN_USERNAME || 'admin';
      }
      if (session.username === adminUsername) isAdmin = true;
    }
  } catch (e) {
    console.warn("[Location Check] Admin check error:", e.message);
  }
  if (isAdmin) {
    console.log("[Location Check] Admin bypass - allowing access");
    return res.json({ ok: true, inside: true, distance: 0, msg: "Admin bypass" });
  }

  if (!lat || !lng) {
    console.log("[Location Check] Missing location:", { lat, lng });
    return res.status(400).json({ ok: false, msg: "Location required" });
  }

  if (Number.isNaN(CONFIG_LOCATION.lat) || Number.isNaN(CONFIG_LOCATION.lng)) {
    console.error("[Location Check] Server location not configured:", CONFIG_LOCATION);
    return res.status(500).json({ ok: false, msg: "Server location not configured" });
  }

  const distance = dist(
    parseFloat(lat),
    parseFloat(lng),
    CONFIG_LOCATION.lat,
    CONFIG_LOCATION.lng
  );

  const allowed = distance <= CONFIG_LOCATION.radiusMeters;
  console.log("[Location Check]", {
    userLocation: { lat: parseFloat(lat), lng: parseFloat(lng) },
    restaurantLocation: { lat: CONFIG_LOCATION.lat, lng: CONFIG_LOCATION.lng },
    radius: CONFIG_LOCATION.radiusMeters,
    distance: Math.round(distance),
    allowed
  });

  // Sliding refresh: if token is close to expiry (< 120s), extend by issuing a new token
  let refreshToken = null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const nowSec = Math.floor(Date.now() / 1000);
    const timeLeft = (decoded.exp || 0) - nowSec;
    if (timeLeft > 0 && timeLeft < 120) {
      refreshToken = signQr({ tableId: payload.tableId }, "10m");
    }
  } catch {}

  res.json({
    ok: allowed,
    inside: allowed,
    distance: Math.round(distance),
    refreshToken,
    msg: allowed
      ? "Inside restaurant radius"
      : "Outside restaurant area, cannot place order"
  });
});

app.post("/api/validate-pin", async (req, res) => {
  const { token, tableId, pin } = req.body;
  const payload = verifyQr(token);
  if (!payload) return res.json({ ok: false });
  if (mongoDb) {
    const t = await mongoDb.collection("tables").findOne({ id: String(tableId) });
    return res.json({ ok: !!t && bcrypt.compareSync(pin, t.pinHash) });
  } else {
    const d = await readData();
    const t = d.tables.find(x => x.id == tableId);
    return res.json({ ok: t ? bcrypt.compareSync(pin, t.pinHash) : false });
  }
});

app.post("/api/orders/create", limiter, async (req, res) => {
  const { token, tableId, items } = req.body;
  const payload = verifyQr(token);
  if (!payload) return res.status(401).json({ ok: false });
  const order = { id: uuidv4(), tableId, items, createdAt: new Date().toISOString() };
  if (mongoDb) {
    await mongoDb.collection("orders").insertOne({ ...order, _id: order.id });
    const all = await mongoDb.collection("orders").find({}).toArray();
    io.emit("orders:update", all);
  } else {
    const d = await readData();
    d.orders.push(order);
    await writeData(d);
    io.emit("orders:update", d.orders);
  }
  sendMail(order);
  res.json({ ok: true });
});

app.get("/api/orders/summary", auth, async (req, res) => {
  let orders = [];
  if (mongoDb) {
    orders = await mongoDb.collection("orders").find({}).toArray();
  } else {
    const d = await readData();
    orders = d.orders || [];
  }

  const summary = {};

  // group by item name
  for (const order of orders) {
    for (const item of order.items) {
      const name = item.name;
      if (!summary[name]) {
        summary[name] = {
          itemName: name,
          totalQty: 0,
          tables: new Set()
        };
      }
      summary[name].totalQty += item.qty;
      summary[name].tables.add(order.tableId);
    }
  }

  // convert Set → Array for JSON
  const result = Object.values(summary).map(s => ({
    itemName: s.itemName,
    totalQty: s.totalQty,
    tables: Array.from(s.tables)
  }));

  res.json({ ok: true, data: result });
});

// ---------- Socket.IO ----------
io.on("connection", s => {
  if (mongoDb) {
    mongoDb.collection("orders").find({}).toArray().then(all => s.emit("orders:update", all));
  } else {
    readData().then(d => s.emit("orders:update", d.orders));
  }
});

// ---------- Start ----------

server.listen(PORT, () => console.log(`✅ Running on http://localhost:${PORT}`));


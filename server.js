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
const CONFIG_LOCATION = {
  lat: Number(process.env.RESTAURANT_LAT) || 14.478144241010149,
  lng: Number(process.env.RESTAURANT_LNG) || 75.88522999510667,
  radiusMeters: Number(process.env.RESTAURANT_RADIUS_METERS || process.env.PROXIMITY_RADIUS_METERS) || 10
};

// Log loaded location config at startup
console.log("[Config] Restaurant Location:", CONFIG_LOCATION);

// ❌ ❌ ❌ GALAT CORS BLOCK HATA DIYA HAI YAHAN SE ❌ ❌ ❌

// ---------- Correct place to create app ----------
const app = express();

// ---------- CORRECT CORS BLOCK (Only this one stays) ----------
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

app.get(Array.from(PROTECTED_PAGES), ensureAdminPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, req.path));
});

app.use(express.static(PUBLIC_DIR));
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
    if (err.code === "ENOENT") {
      const defaultData = {
        admin: { username: process.env.ADMIN_USERNAME || "admin" },
        tables: [],
        orders: []
      };
      await writeData(defaultData);
      return defaultData;
    }
    throw err;
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
  try {
    await connectMongoIfConfigured();
  } catch (e) {
    console.warn("MongoDB connection failed:", e.message);
  }
}
await init();

// ---------- API ----------
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (mongoDb) {
    const adm = await mongoDb.collection("admin").findOne({ _id: "admin" });
    if (!adm || username !== adm.username)
      return res.status(401).json({ ok: false, msg: "Invalid username" });
    if (!bcrypt.compareSync(password, adm.passwordHash))
      return res.status(401).json({ ok: false, msg: "Invalid password" });
  } else {
    const d = await readData();
    if (username !== d.admin.username)
      return res.status(401).json({ ok: false, msg: "Invalid username" });
    if (!bcrypt.compareSync(password, d.admin.passwordHash))
      return res.status(401).json({ ok: false, msg: "Invalid password" });
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
  const qrUrl = `${req.protocol}://${req.get("host")}/index.html?token=${encodeURIComponent(token)}`;
  let qrImageData = null;
  try {
    qrImageData = await QRCode.toDataURL(qrUrl, { errorCorrectionLevel: "L", margin: 0, width: 180 });
  } catch (e) {
    console.warn("QR generation failed", e.message);
  }
  res.json({ ok: true, qrUrl, qrImageData, expiresInSeconds: 600 });
});

// Frontend QR generator
app.post("/api/qr/generate", auth, async (req, res) => {
  try {
    const table = req.body.table;
    const baseUrl = String(req.body.baseUrl || "").trim();
    if (!table) return res.status(400).json({ ok: false, message: "table required" });
    if (!baseUrl) return res.status(400).json({ ok: false, message: "baseUrl required" });
    const token = signQr({ tableId: String(table) }, "10m");
    const url = `${baseUrl}${baseUrl.includes("?") ? "&" : "?"}token=${encodeURIComponent(token)}`;
    let qrImageData = null;
    try {
      qrImageData = await QRCode.toDataURL(url, { errorCorrectionLevel: "L", margin: 0, width: 180 });
    } catch (e) {}
    res.json({ ok: true, url, qrImageData, expiresInSeconds: 600 });
  } catch (e) {
    res.status(500).json({ ok: false, message: "QR generation error" });
  }
});

app.post("/api/validate-location", async (req, res) => {
  const { token, lat, lng } = req.body;
  const payload = verifyQr(token);
  if (!payload)
    return res.json({ ok: false, msg: "Invalid QR token" });

  if (!lat || !lng)
    return res.status(400).json({ ok: false, msg: "Location required" });

  const distance = dist(parseFloat(lat), parseFloat(lng), CONFIG_LOCATION.lat, CONFIG_LOCATION.lng);
  const allowed = distance <= CONFIG_LOCATION.radiusMeters;

  console.log("[Location Check]", {
    userLocation: { lat: parseFloat(lat), lng: parseFloat(lng) },
    restaurantLocation: CONFIG_LOCATION,
    radius: CONFIG_LOCATION.radiusMeters,
    distance: Math.round(distance),
    allowed
  });

  res.json({
    ok: allowed,
    inside: allowed,
    distance: Math.round(distance),
    msg: allowed ? "Inside restaurant radius" : "Outside restaurant area, cannot place order"
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

  const order = {
    id: uuidv4(),
    tableId,
    items,
    createdAt: new Date().toISOString()
  };

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

  // Send email
  try {
    if (process.env.NOTIFY_EMAIL) {
      await mailer.sendMail({
        from: process.env.SMTP_USER,
        to: process.env.NOTIFY_EMAIL,
        subject: `New order #${order.id} - Table ${order.tableId}`,
        text: order.items.map(i => `${i.name} x${i.qty}`).join("\n")
      });
    }
  } catch {}

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
server.listen(PORT, () =>
  console.log(`✅ Running on http://localhost:${PORT}`)
);

const cluster = require("cluster");
const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const http = require("http");
const os = require("os");
const path = require("path");
const { URL } = require("url");

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const JSON_DB_PATH = path.join(DATA_DIR, "db.json");
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const HAS_POSTGRES = Boolean(process.env.DATABASE_URL);
const WORKERS = HAS_POSTGRES
  ? Number(process.env.WEB_CONCURRENCY || Math.max(1, Math.min(os.cpus().length, 4)))
  : 1;
const MAX_BODY_BYTES = 64 * 1024;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const ADMIN_USER = process.env.ADMIN_USER || "auratabel";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "auratabel4000";
const ADMIN_SESSION_HOURS = Number(process.env.ADMIN_SESSION_HOURS || 8);
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const NOTIFY_TO = process.env.NOTIFY_TO || "";
const NOTIFY_FROM = process.env.NOTIFY_FROM || SMTP_USER || "bookings@auratable.local";
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

const BLOCKED_STATIC = new Set([
  "server.js",
  "package.json",
  "package-lock.json",
  ".env",
  ".env.example",
  ".htaccess",
  "_headers"
]);

const rateBuckets = new Map();

function securityHeaders() {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; upgrade-insecure-requests; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; frame-src https://www.google.com; connect-src 'self' http://localhost:3400 http://127.0.0.1:3400 https:; form-action 'self' https://api.web3forms.com;",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(self), payment=()",
    "X-Frame-Options": "SAMEORIGIN"
  };
}

function corsHeaders(req) {
  const origin = req.headers.origin || "";
  const allowedOrigins = new Set([
    "http://localhost:3400",
    "http://127.0.0.1:3400",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
    ...FRONTEND_ORIGINS
  ]);

  if (!allowedOrigins.has(origin)) return {};

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS",
    "Vary": "Origin"
  };
}

function send(res, status, body, headers = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    ...securityHeaders(),
    "Content-Type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    ...headers
  });
  res.end(payload);
}

function sendJson(res, status, data, headers = {}) {
  send(res, status, data, headers);
}

function clientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

function rateLimit(req, res, key, limit, windowMs) {
  const now = Date.now();
  const bucketKey = `${clientIp(req)}:${key}`;
  const bucket = rateBuckets.get(bucketKey) || { count: 0, resetAt: now + windowMs };

  if (bucket.resetAt <= now) {
    bucket.count = 0;
    bucket.resetAt = now + windowMs;
  }

  bucket.count += 1;
  rateBuckets.set(bucketKey, bucket);

  if (bucket.count > limit) {
    sendJson(res, 429, { error: "Too many requests. Please wait a moment and try again." });
    return false;
  }

  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(key);
  }
}, 60_000).unref();

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Request body is too large."), { status: 413 }));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(Object.assign(new Error("Invalid JSON request body."), { status: 400 }));
      }
    });
  });
}

function text(value, max = 300) {
  return String(value || "")
    .replace(/[<>]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ""));
}

function isIsoDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ""))) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime());
}

function validateReservation(data) {
  const reservation = {
    name: text(data.name, 120),
    email: text(data.email, 180).toLowerCase(),
    phone: text(data.phone, 40),
    date: text(data.date, 20),
    time: text(data.time, 30),
    guests: text(data.guests, 30),
    occasion: text(data.occasion, 80) || "Dinner",
    notes: text(data.notes, 700)
  };

  const missing = ["name", "email", "phone", "date", "time", "guests"].filter(field => !reservation[field]);
  if (missing.length) return { error: `Missing fields: ${missing.join(", ")}` };
  if (!isEmail(reservation.email)) return { error: "Please enter a valid email address." };
  if (!isIsoDate(reservation.date)) return { error: "Please choose a valid reservation date." };

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const requested = new Date(`${reservation.date}T00:00:00`);
  if (requested < today) return { error: "Reservation date cannot be in the past." };

  return { reservation };
}

async function loadPgPool() {
  if (!HAS_POSTGRES) return null;
  try {
    const { Pool } = require("pg");
    return new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: false },
      max: Number(process.env.PG_POOL_MAX || 20),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 8_000
    });
  } catch (error) {
    console.warn("PostgreSQL driver is not installed. Run npm install before using DATABASE_URL.");
    throw error;
  }
}

class JsonDatabase {
  constructor(filePath) {
    this.filePath = filePath;
    this.queue = Promise.resolve();
  }

  async init() {
    await fsp.mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      await fsp.access(this.filePath);
    } catch {
      await this.write({
        reservations: [],
        newsletter: []
      });
    }
  }

  async read() {
    const raw = await fsp.readFile(this.filePath, "utf8");
    return JSON.parse(raw || "{\"reservations\":[],\"newsletter\":[]}");
  }

  async write(data) {
    await fsp.writeFile(this.filePath, JSON.stringify(data, null, 2), "utf8");
  }

  async mutate(mutator) {
    this.queue = this.queue.then(async () => {
      const db = await this.read();
      const result = await mutator(db);
      await this.write(db);
      return result;
    });
    return this.queue;
  }

  async createReservation(record) {
    return this.mutate(db => {
      db.reservations.unshift(record);
      return record;
    });
  }

  async createSubscriber(record) {
    return this.mutate(db => {
      const existing = db.newsletter.find(item => item.email === record.email);
      if (existing) return existing;
      db.newsletter.unshift(record);
      return record;
    });
  }

  async listReservations() {
    const db = await this.read();
    return db.reservations;
  }

  async updateReservationStatus(id, status) {
    return this.mutate(db => {
      const reservation = db.reservations.find(item => item.id === id);
      if (!reservation) return null;
      reservation.status = status;
      reservation.updatedAt = new Date().toISOString();
      return reservation;
    });
  }

  async listSubscribers() {
    const db = await this.read();
    return db.newsletter;
  }
}

class PostgresDatabase {
  constructor(pool) {
    this.pool = pool;
  }

  async init() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS reservations (
        id UUID PRIMARY KEY,
        booking_code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        reservation_date DATE NOT NULL,
        reservation_time TEXT NOT NULL,
        guests TEXT NOT NULL,
        occasion TEXT NOT NULL,
        notes TEXT,
        status TEXT NOT NULL DEFAULT 'Pending',
        ip_hash TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS newsletter_subscribers (
        id UUID PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        ip_hash TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_reservations_date ON reservations (reservation_date);
      CREATE INDEX IF NOT EXISTS idx_reservations_status ON reservations (status);
    `);
  }

  rowToReservation(row) {
    return {
      id: row.id,
      bookingCode: row.booking_code,
      name: row.name,
      email: row.email,
      phone: row.phone,
      date: row.reservation_date instanceof Date ? row.reservation_date.toISOString().slice(0, 10) : row.reservation_date,
      time: row.reservation_time,
      guests: row.guests,
      occasion: row.occasion,
      notes: row.notes || "",
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  async createReservation(record) {
    const result = await this.pool.query(
      `INSERT INTO reservations
      (id, booking_code, name, email, phone, reservation_date, reservation_time, guests, occasion, notes, status, ip_hash, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *`,
      [
        record.id,
        record.bookingCode,
        record.name,
        record.email,
        record.phone,
        record.date,
        record.time,
        record.guests,
        record.occasion,
        record.notes,
        record.status,
        record.ipHash,
        record.createdAt,
        record.updatedAt
      ]
    );
    return this.rowToReservation(result.rows[0]);
  }

  async createSubscriber(record) {
    const result = await this.pool.query(
      `INSERT INTO newsletter_subscribers (id, email, ip_hash, created_at)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
       RETURNING *`,
      [record.id, record.email, record.ipHash, record.createdAt]
    );
    return {
      id: result.rows[0].id,
      email: result.rows[0].email,
      createdAt: result.rows[0].created_at
    };
  }

  async listReservations() {
    const result = await this.pool.query("SELECT * FROM reservations ORDER BY reservation_date DESC, created_at DESC LIMIT 500");
    return result.rows.map(row => this.rowToReservation(row));
  }

  async updateReservationStatus(id, status) {
    const result = await this.pool.query(
      "UPDATE reservations SET status = $2, updated_at = NOW() WHERE id = $1 RETURNING *",
      [id, status]
    );
    return result.rows[0] ? this.rowToReservation(result.rows[0]) : null;
  }

  async listSubscribers() {
    const result = await this.pool.query("SELECT id, email, created_at FROM newsletter_subscribers ORDER BY created_at DESC LIMIT 500");
    return result.rows.map(row => ({
      id: row.id,
      email: row.email,
      createdAt: row.created_at
    }));
  }
}

let db;

function ipHash(req) {
  return crypto.createHash("sha256").update(clientIp(req)).digest("hex");
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || "";
  const match = cookie.split(";").map(part => part.trim()).find(part => part.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : "";
}

function base64Url(input) {
  return Buffer.from(input).toString("base64url");
}

function sign(value) {
  return crypto.createHmac("sha256", ADMIN_PASSWORD).update(value).digest("base64url");
}

function createSession() {
  const payload = base64Url(JSON.stringify({
    user: ADMIN_USER,
    exp: Date.now() + ADMIN_SESSION_HOURS * 60 * 60 * 1000,
    nonce: crypto.randomBytes(16).toString("hex")
  }));
  return `${payload}.${sign(payload)}`;
}

function verifySession(token) {
  const [payload, signature] = String(token || "").split(".");
  if (!payload || !signature || !timingSafeEqualText(signature, sign(payload))) return false;

  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return session.user === ADMIN_USER && session.exp > Date.now();
  } catch {
    return false;
  }
}

function requireAdmin(req, res) {
  const token = getCookie(req, "aura_admin");
  if (!verifySession(token)) {
    sendJson(res, 401, { error: "Admin login required." });
    return false;
  }
  return true;
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

async function sendMail({ to, subject, text: body }) {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !to) {
    console.warn("SMTP email not sent: missing SMTP_HOST, SMTP_USER, SMTP_PASS, or recipient address.");
    return false;
  }

  let nodemailer;
  try {
    nodemailer = require("nodemailer");
  } catch {
    console.warn("Nodemailer is not installed. Run npm install to enable email notifications.");
    return false;
  }

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    requireTLS: SMTP_PORT === 587,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });

  try {
    await transporter.sendMail({
      from: NOTIFY_FROM,
      to,
      subject,
      text: body
    });
    return true;
  } catch (error) {
    console.error("SMTP email failed:", error?.message || error);
    throw error;
  }
}

async function notifyReservation(record) {
  const ownerEmail = NOTIFY_TO || SMTP_USER || "";
  const guestEmail = record.email || "";
  const bookingSummary = [
    `Booking Code: ${record.bookingCode}`,
    `Name: ${record.name}`,
    `Email: ${record.email}`,
    `Phone: ${record.phone}`,
    `Date: ${record.date}`,
    `Time: ${record.time}`,
    `Guests: ${record.guests}`,
    `Occasion: ${record.occasion || "Dinner"}`,
    `Special Request: ${record.notes || "None"}`
  ].join("\n");

  const adminSubject = `New Booking: ${record.bookingCode}`;
  const guestSubject = `Reservation confirmed: ${record.bookingCode}`;
  const adminBody = `A new reservation was submitted.\n\n${bookingSummary}`;
  const guestBody = `Thank you for booking at Aura Table.\n\n${bookingSummary}\n\nWe will confirm your table shortly.`;

  console.log("Reservation notifications starting", {
    bookingCode: record.bookingCode,
    ownerEmail,
    guestEmail,
    smtpConfigured: Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS),
    notifyFrom: NOTIFY_FROM,
    smtpPort: SMTP_PORT
  });

  const smtpTasks = [];
  if (ownerEmail) {
    smtpTasks.push(sendMail({ to: ownerEmail, subject: adminSubject, text: adminBody }));
  }
  if (guestEmail && guestEmail !== ownerEmail) {
    smtpTasks.push(sendMail({ to: guestEmail, subject: guestSubject, text: guestBody }));
  }

  const smtpResults = await Promise.allSettled(smtpTasks);
  const smtpSent = smtpResults.some(result => result.status === "fulfilled" && result.value);

  if (smtpSent) {
    console.log("Reservation notifications sent successfully", {
      bookingCode: record.bookingCode,
      ownerEmail,
      guestEmail
    });
    return;
  }

  const failedReasons = smtpResults
    .filter(result => result.status === "rejected")
    .map(result => result.reason?.message || String(result.reason || "unknown error"));

  if (failedReasons.length > 0) {
    console.warn("SMTP notification failed. Falling back to Web3Forms. Reasons:", failedReasons.join(" | "));
  } else {
    console.warn("SMTP notification was not sent. Falling back to Web3Forms.");
  }

  try {
    const web3formsResponse = await fetch('https://api.web3forms.com/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        access_key: "8cedcb5e-2953-4d61-a715-53939e49d45a",
        subject: adminSubject,
        from_name: "Aura Table Notifications",
        Name: record.name,
        Email: record.email,
        Phone: record.phone,
        Date: record.date,
        Time: record.time,
        Guests: record.guests,
        Occasion: record.occasion,
        Notes: record.notes || "None"
      })
    });
    console.log("Web3Forms fallback status", {
      bookingCode: record.bookingCode,
      status: web3formsResponse.status
    });
  } catch (error) {
    console.log("Notification fallback failed:", error);
  }
}

async function handleReservation(req, res) {
  if (!rateLimit(req, res, "reservation", 12, 10 * 60_000)) return;

  const data = await parseBody(req);
  const { reservation, error } = validateReservation(data);
  if (error) {
    sendJson(res, 400, { error });
    return;
  }

  const now = new Date().toISOString();
  const record = {
    id: crypto.randomUUID(),
    bookingCode: `AT-${crypto.randomInt(100000, 999999)}`,
    createdAt: now,
    updatedAt: now,
    status: "Pending",
    ipHash: ipHash(req),
    ...reservation
  };

  console.log("Reservation received", {
    bookingCode: record.bookingCode,
    email: record.email,
    phone: record.phone,
    date: record.date,
    time: record.time,
    guests: record.guests,
    occasion: record.occasion
  });

  const saved = await db.createReservation(record);
  console.log("Reservation saved", { bookingCode: saved.bookingCode });
  notifyReservation(saved).catch(error => console.warn("Reservation notification failed:", error.message));
  sendJson(res, 201, {
    message: "Reserved successfully",
    bookingCode: saved.bookingCode
  });
}

async function handleNewsletter(req, res) {
  if (!rateLimit(req, res, "newsletter", 8, 10 * 60_000)) return;

  const data = await parseBody(req);
  const email = text(data.email, 180).toLowerCase();
  if (!isEmail(email)) {
    sendJson(res, 400, { error: "Please enter a valid email address." });
    return;
  }

  await db.createSubscriber({
    id: crypto.randomUUID(),
    email,
    createdAt: new Date().toISOString(),
    ipHash: ipHash(req)
  });

  sendJson(res, 201, { message: "Subscribed successfully" });
}

async function handleAdminLogin(req, res) {
  if (!rateLimit(req, res, "admin-login", 8, 10 * 60_000)) return;
  const data = await parseBody(req);
  const userOk = timingSafeEqualText(text(data.username, 80), ADMIN_USER);
  const passwordOk = timingSafeEqualText(String(data.password || ""), ADMIN_PASSWORD);

  if (!userOk || !passwordOk || (IS_PRODUCTION && ADMIN_PASSWORD === "change-this-password")) {
    sendJson(res, 401, { error: "Invalid admin credentials." });
    return;
  }

  const token = createSession();
  sendJson(res, 200, { message: "Logged in" }, {
    "Set-Cookie": `aura_admin=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${ADMIN_SESSION_HOURS * 60 * 60}${IS_PRODUCTION ? "; Secure" : ""}`
  });
}

async function handleAdminLogout(req, res) {
  sendJson(res, 200, { message: "Logged out" }, {
    "Set-Cookie": `aura_admin=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${IS_PRODUCTION ? "; Secure" : ""}`
  });
}

async function handleAdminApi(req, res, url) {
  if (req.method === "POST" && url.pathname === "/api/admin/login") {
    await handleAdminLogin(req, res);
    return;
  }

  if (!requireAdmin(req, res)) return;

  if (req.method === "POST" && url.pathname === "/api/admin/logout") {
    await handleAdminLogout(req, res);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/admin/summary") {
    const [reservations, subscribers] = await Promise.all([
      db.listReservations(),
      db.listSubscribers()
    ]);
    const today = new Date().toISOString().slice(0, 10);
    sendJson(res, 200, {
      totalReservations: reservations.length,
      todayReservations: reservations.filter(item => item.date === today).length,
      pendingReservations: reservations.filter(item => item.status === "Pending").length,
      subscribers: subscribers.length
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/admin/reservations") {
    sendJson(res, 200, { reservations: await db.listReservations() });
    return;
  }

  if (req.method === "PATCH" && url.pathname.startsWith("/api/admin/reservations/")) {
    const id = url.pathname.split("/").pop();
    const data = await parseBody(req);
    const allowed = new Set(["Pending", "Confirmed", "Cancelled", "Completed"]);
    const status = text(data.status, 40);
    if (!allowed.has(status)) {
      sendJson(res, 400, { error: "Invalid reservation status." });
      return;
    }
    const reservation = await db.updateReservationStatus(id, status);
    if (!reservation) {
      sendJson(res, 404, { error: "Reservation not found." });
      return;
    }
    sendJson(res, 200, { reservation });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/admin/newsletter") {
    sendJson(res, 200, { subscribers: await db.listSubscribers() });
    return;
  }

  sendJson(res, 404, { error: "Admin route not found." });
}

async function handleApi(req, res, url) {
  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, 200, {
      status: "healthy",
      service: "Aura Table API",
      storage: HAS_POSTGRES ? "postgresql" : "local-json",
      worker: cluster.worker?.id || "single",
      timestamp: new Date().toISOString()
    });
    return;
  }

  if (url.pathname.startsWith("/api/admin/")) {
    await handleAdminApi(req, res, url);
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/reservations") {
    await handleReservation(req, res);
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/newsletter") {
    await handleNewsletter(req, res);
    return;
  }

  sendJson(res, 404, { error: "API route not found." });
}

function serveStatic(req, res, url) {
  const cleanPath = decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname);
  const filePath = path.normalize(path.join(ROOT, cleanPath));

  if (!filePath.startsWith(ROOT) || BLOCKED_STATIC.has(path.basename(filePath)) || filePath.includes(`${path.sep}data${path.sep}`)) {
    send(res, 403, "Forbidden");
    return;
  }

  fs.stat(filePath, (statError, stat) => {
    if (statError || !stat.isFile()) {
      send(res, 404, "Not found");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const headers = {
      "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
      "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=604800, immutable"
    };

    res.writeHead(200, { ...securityHeaders(), ...headers });
    fs.createReadStream(filePath).pipe(res);
  });
}

async function requestHandler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const originalWriteHead = res.writeHead.bind(res);
    res.writeHead = (statusCode, headers = {}) => originalWriteHead(statusCode, {
      ...corsHeaders(req),
      ...headers
    });

    if (req.method === "OPTIONS") {
      res.writeHead(204, securityHeaders());
      res.end();
      return;
    }

    if (IS_PRODUCTION && req.headers["x-forwarded-proto"] === "http") {
      res.writeHead(301, {
        Location: `https://${req.headers.host}${req.url}`,
        ...securityHeaders()
      });
      res.end();
      return;
    }

    if (!["GET", "HEAD", "POST", "PATCH"].includes(req.method)) {
      sendJson(res, 405, { error: "Method not allowed." });
      return;
    }

    if (url.pathname.startsWith("/api/")) {
      await handleApi(req, res, url);
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      sendJson(res, 405, { error: "Method not allowed." });
      return;
    }

    serveStatic(req, res, url);
  } catch (error) {
    const status = error.status || 500;
    console.error(error);
    sendJson(res, status, {
      error: status === 500 ? "Server error. Please try again." : error.message
    });
  }
}

async function initDatabase() {
  const pool = await loadPgPool();
  db = pool ? new PostgresDatabase(pool) : new JsonDatabase(JSON_DB_PATH);
  await db.init();
}

async function startWorker() {
  await initDatabase();
  const server = http.createServer(requestHandler);
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  server.requestTimeout = 30_000;
  server.maxHeadersCount = 80;

  server.listen(PORT, HOST, () => {
    const storage = HAS_POSTGRES ? "PostgreSQL" : "local JSON database";
    console.log(`Aura Table running on http://${HOST}:${PORT} using ${storage} with worker ${cluster.worker?.id || "single"}`);
  });
}

if (cluster.isPrimary && WORKERS > 1) {
  console.log(`Starting Aura Table with ${WORKERS} workers on port ${PORT}`);
  for (let index = 0; index < WORKERS; index += 1) cluster.fork();
  cluster.on("exit", worker => {
    console.warn(`Worker ${worker.id} stopped. Starting a replacement.`);
    cluster.fork();
  });
} else {
  startWorker().catch(error => {
    console.error("Failed to start Aura Table:", error);
    process.exit(1);
  });
}

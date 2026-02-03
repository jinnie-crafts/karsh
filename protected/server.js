import fs from "fs";
import fetch from "node-fetch";
import express from "express";
import path from "path";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import "dotenv/config";
import { fileURLToPath } from "url";

/* ------------------ SETUP ------------------ */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

/* ------------------ CONSTANTS ------------------ */
const USERS_PATH = path.join(__dirname, "users.json");
const HISTORY_PATH = path.join(__dirname, "login-history.json");

const validTokens = new Set();
const failedAttempts = {}; // { email: { count, lockUntil } }

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

/* ------------------ MIDDLEWARE ------------------ */
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

/* ------------------ HELPERS ------------------ */
function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_PATH, "utf-8"));
}

function loadHistory() {
  if (!fs.existsSync(HISTORY_PATH)) return [];
  return JSON.parse(fs.readFileSync(HISTORY_PATH, "utf-8"));
}

function saveHistory(entry) {
  const history = loadHistory();
  history.unshift(entry);
  fs.writeFileSync(HISTORY_PATH, JSON.stringify(history, null, 2));
}

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress ||
    "Unknown"
  );
}

async function getLocation(ip) {
  try {
    const res = await fetch(`https://ipapi.co/${ip}/json/`);
    return await res.json();
  } catch {
    return {};
  }
}

// Telegram alert
async function sendTelegramAlert(message) {
  const url = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;

  await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: process.env.TELEGRAM_CHAT_ID,
      text: message
    })
  });
}

async function sendLoginAlert(email, req, success, locked = false) {
  const ip = getClientIP(req);
  const location = await getLocation(ip);

  const message = `
🔐 LOGIN ${success ? "SUCCESS" : "FAILED"}${locked ? " (LOCKED)" : ""}

Email: ${email}
IP: ${ip}
City: ${location.city || "Unknown"}
Country: ${location.country_name || "Unknown"}
Time: ${new Date().toLocaleString()}
`;

  await sendTelegramAlert(message);

  saveHistory({
    email,
    ip,
    city: location.city || "Unknown",
    country: location.country_name || "Unknown",
    time: new Date().toISOString(),
    success,
    locked
  });
}

/* ------------------ AUTH MIDDLEWARE ------------------ */
function requireAuth(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token || !validTokens.has(token)) {
    return res
      .status(401)
      .sendFile(path.join(__dirname, "../public/index.html"));
  }
  next();
}

/* ------------------ ROUTES ------------------ */

// Health
app.get("/health", (req, res) => res.send("ok"));

// Login
app.post("/verify", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ ok: false });

  const now = Date.now();

  // Lock check
  if (failedAttempts[email]?.lockUntil > now) {
    await sendLoginAlert(email, req, false, true);
    return res.status(403).json({ ok: false, locked: true });
  }

  const users = loadUsers();
  const user = users[email];
  if (!user) {
    return res.status(401).json({ ok: false });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);

  if (!valid) {
    failedAttempts[email] ??= { count: 0, lockUntil: 0 };
    failedAttempts[email].count++;

    if (failedAttempts[email].count >= 3) {
      failedAttempts[email].lockUntil = now + 10 * 60 * 1000;
      failedAttempts[email].count = 0;
      await sendLoginAlert(email, req, false, true);
      return res.status(403).json({ ok: false, locked: true });
    }

    await sendLoginAlert(email, req, false);
    return res.status(401).json({ ok: false });
  }

  // Success
  delete failedAttempts[email];

  const token = generateToken();
  validTokens.add(token);

  res.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  });

  await sendLoginAlert(email, req, true);
  res.json({ ok: true });
});

// Logout
app.post("/logout", (req, res) => {
  const token = req.cookies?.auth_token;
  if (token) validTokens.delete(token);

  res.clearCookie("auth_token");
  res.json({ ok: true });
});

// Login history page (JSON)
app.get("/protected/history", requireAuth, (req, res) => {
  res.json(loadHistory());
});

/* ------------------ STATIC FILES ------------------ */
const publicPath = path.join(__dirname, "../public");
const sitePath = path.join(__dirname, "site");

app.use(express.static(publicPath));
app.use("/protected/site", requireAuth, express.static(sitePath));

app.get("/protected/site", requireAuth, (req, res) => {
  res.sendFile(path.join(sitePath, "index.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
});

/* ------------------ START SERVER ------------------ */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () =>
  console.log(`✅ Server running on http://localhost:${PORT}`)
);

import fs from "fs";
import nodemailer from "nodemailer";
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
const validTokens = new Set();

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

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.ALERT_EMAIL,
    pass: process.env.ALERT_EMAIL_PASS
  }
});

async function sendLoginAlert(email, req) {
  const ip = getClientIP(req);
  const location = await getLocation(ip);

  const message = `
🚨 NEW LOGIN ALERT

Email: ${email}
IP: ${ip}
City: ${location.city || "Unknown"}
Country: ${location.country_name || "Unknown"}
Time: ${new Date().toLocaleString()}
`;

  await transporter.sendMail({
    from: `"Security Alert" <${process.env.ALERT_EMAIL}>`,
    to: process.env.ALERT_EMAIL,
    subject: "🚨 Login Detected",
    text: message
  });
   // Telegram alert
  await sendTelegramAlert(message);
}

//tg bot service login alert system
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

// Health check
app.get("/health", (req, res) => res.send("ok"));

// Login (email + password)
app.post("/verify", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ ok: false });
  }

  const users = loadUsers();
  const user = users[email];
  if (!user) {
    return res.status(401).json({ ok: false });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ ok: false });
  }

  const token = generateToken();
  validTokens.add(token);

  res.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
    // session cookie (dies on browser close)
  });

  await sendLoginAlert(email, req);

  res.json({ ok: true });
});

// Logout
app.post("/logout", (req, res) => {
  const token = req.cookies?.auth_token;
  if (token) validTokens.delete(token);

  res.clearCookie("auth_token", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  });

  res.json({ ok: true });
});

/* ------------------ STATIC FILES ------------------ */
const publicPath = path.join(__dirname, "../public");
const sitePath = path.join(__dirname, "site");

// Public login page
app.use(express.static(publicPath));

// Protected site
app.use("/protected/site", requireAuth, express.static(sitePath));

app.get("/protected/site", requireAuth, (req, res) => {
  res.sendFile(path.join(sitePath, "index.html"));
});

app.get("/protected/site/*", requireAuth, (req, res) => {
  res.sendFile(path.join(sitePath, "index.html"));
});

// Fallback → login
app.get("*", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
});

/* ------------------ START SERVER ------------------ */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () =>
  console.log(`✅ Server running on http://localhost:${PORT}`)
);

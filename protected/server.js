import express from "express";
import path from "path";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import "dotenv/config";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- CONFIG ---
const PASSWORD_HASH = process.env.PASSWORD_HASH;
if (!PASSWORD_HASH) {
  console.error("❌ Missing PASSWORD_HASH in environment variables");
  process.exit(1);
}

const validTokens = new Set();

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// --- MIDDLEWARE ---
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// --- AUTH CHECK ---
function requireAuth(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token || !validTokens.has(token)) {
    return res.status(401).sendFile(path.join(__dirname, "../public/index.html"));
  }
  next();
}

// --- ROUTES ---
app.get("/health", (req, res) => res.send("ok"));

app.post("/verify", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ ok: false, error: "Password required" });

  try {
    const valid = await bcrypt.compare(password, PASSWORD_HASH);
    if (!valid) return res.status(401).json({ ok: false, error: "Invalid password" });

    const token = generateToken();
    validTokens.add(token);

    res.cookie("auth_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Password check failed:", err);
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/logout", (req, res) => {
  const token = req.cookies?.auth_token;
  if (token) validTokens.delete(token);

  res.clearCookie("auth_token", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });

  res.json({ ok: true });
});

// --- PATHS ---
const publicPath = path.join(__dirname, "../public");
const sitePath = path.join(__dirname, "site");

// Serve public login page
app.use(express.static(publicPath));

// ✅ Serve main site assets (CSS, JS, etc.)
app.use("/protected/site", requireAuth, express.static(sitePath));

// ✅ Serve main site index.html for /protected/site
app.get("/protected/site", requireAuth, (req, res) => {
  res.sendFile(path.join(sitePath, "index.html"));
});

// ✅ SPA fallback for any deeper site route
app.get("/protected/site/*", requireAuth, (req, res) => {
  res.sendFile(path.join(sitePath, "index.html"));
});

// Fallback to login page
app.get("*", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
});

// --- START SERVER ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

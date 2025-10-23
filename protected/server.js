import express from "express";
import path from "path";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { totp } from "otplib";
import 'dotenv/config';
import { fileURLToPath } from "url";

// ES module __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// TOTP secret
const SECRET = process.env.TOTP_SECRET || "karsh.beta.jinnie.akka.bcha";
totp.options = { step: 120 }; // 2 minutes step

// In-memory session tokens
const validTokens = new Set();

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Verify TOTP
app.post("/verify", (req, res) => {
  const { code } = req.body;
  if (typeof code !== "string") return res.status(400).json({ ok: false });

  if (!totp.check(code, SECRET)) return res.status(401).json({ ok: false });

  const token = generateToken();
  validTokens.add(token);

  res.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });

  return res.json({ ok: true });
});

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token || !validTokens.has(token)) return res.status(401).send("Unauthorized");
  next();
}

// Logout
app.post("/logout", (req, res) => {
  const token = req.cookies?.auth_token;
  if (token) validTokens.delete(token);
  res.clearCookie("auth_token");
  res.json({ ok: true });
});

// Serve public folder (login page) — up one level from /protected
const publicPath = path.join(__dirname, "..", "public");
app.use(express.static(publicPath));

// Serve protected folder (backend + content)
app.use("/protected", requireAuth, express.static(__dirname));

// Fallback for SPA routes
app.get("*", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

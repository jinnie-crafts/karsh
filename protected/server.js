import express from "express";
import path from "path";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { totp } from "otplib";
import 'dotenv/config';

const app = express();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// TOTP secret from environment variable
const SECRET = process.env.TOTP_SECRET || "karsh.beta.jinnie.akka.bcha";
totp.options = { step: 120 }; // 2 minutes step

// In-memory token store
const validTokens = new Set();

// Generate random session token
function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// TOTP verification endpoint
app.post("/verify", (req, res) => {
  const { code } = req.body;
  if (typeof code !== "string") return res.status(400).json({ ok: false });

  const ok = totp.check(code, SECRET);
  if (!ok) return res.status(401).json({ ok: false });

  const token = generateToken();
  validTokens.add(token);

  // Session cookie (expires on tab close)
  res.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });

  return res.json({ ok: true });
});

// Middleware to protect routes
function requireAuth(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token || !validTokens.has(token)) return res.status(401).send("Unauthorized");
  next();
}

// Logout endpoint
app.post("/logout", (req, res) => {
  const token = req.cookies?.auth_token;
  if (token) validTokens.delete(token);
  res.clearCookie("auth_token");
  res.json({ ok: true });
});

// Serve public folder at root
app.use(express.static(path.join(process.cwd(), "public")));

// Serve protected folder with authentication
app.use("/protected", requireAuth, express.static(path.join(process.cwd(), "protected")));

// Fallback: any unknown route serves login page
app.get("*", (req, res) => {
  res.sendFile(path.join(process.cwd(), "public", "index.html"));
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

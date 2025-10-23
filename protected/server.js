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

// --- Config ---
const PASSWORD_HASH = process.env.PASSWORD_HASH;
if (!PASSWORD_HASH) {
  console.error("⚠️  ERROR: PASSWORD_HASH not set in environment variables!");
  process.exit(1);
}

const validTokens = new Set();

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// --- Middleware ---
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token || !validTokens.has(token)) return res.status(401).send("Unauthorized");
  next();
}

// --- Routes ---

// Login route
app.post("/verify", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ ok: false, error: "Password required." });

  try {
    const isValid = await bcrypt.compare(password, PASSWORD_HASH);
    if (!isValid) return res.status(401).json({ ok: false, error: "Invalid password." });

    const token = generateToken();
    validTokens.add(token);

    res.cookie("auth_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 6 * 60 * 60 * 1000, // 6 hours
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("Password check failed:", err);
    return res.status(500).json({ ok: false, error: "Server error." });
  }
});

// Logout route
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

// Serve public folder (login page)
const publicPath = path.join(__dirname, "..", "public");
app.use(express.static(publicPath));

// Serve protected folder (website content)
app.use("/protected", requireAuth, express.static(__dirname));

// SPA fallback for protected routes
app.get("/protected/*", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// SPA fallback for public routes
app.get("*", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

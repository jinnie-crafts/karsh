import express from "express";
import path from "path";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { totp } from "otplib";

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// Your secret key (same one in Authenticator app)
const SECRET = "karsh.beta.jinnie.akka.bcha";
totp.options = { step: 120 }; // 2-minute rotating TOTP code

// Store issued tokens
const validTokens = new Set();

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Verify TOTP and set cookie
app.post("/verify", (req, res) => {
  const { code } = req.body;
  if (typeof code !== "string") return res.status(400).json({ ok: false });

  const ok = totp.check(code, SECRET);
  if (!ok) return res.status(401).json({ ok: false });

  const token = generateToken();
  validTokens.add(token);

  // Session cookie (expires when tab/browser closes)
  res.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });

  return res.json({ ok: true });
});

// Middleware to check cookie
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

// Serve files
app.use(express.static(path.join(process.cwd(), "public")));
app.use("/protected", requireAuth, express.static(path.join(process.cwd(), "protected")));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));


import express from "express";
import path from "path";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { totp } from "otplib";
import bcrypt from 'bcrypt'; // <-- Import bcrypt for secure password hashing
import 'dotenv/config';
import { fileURLToPath } from "url";

// ES module __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- Configuration ---

// Retrieve the SECURE HASH from the environment variable (not visible in source code)
const PASSWORD_HASH = process.env.PASSWORD_HASH;

// TOTP secret from environment
const SECRET = process.env.TOTP_SECRET || "JBSWY3DPEHPK3PXP"; 

// Set TOTP options: 30-second step, with a window of 1 (checks current, prev, next)
totp.options = { step: 30, window: 1 }; 

// In-memory session tokens
const validTokens = new Set();

function generateToken() {
    return crypto.randomBytes(32).toString("hex");
}

// --- Middleware ---
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// Auth middleware (requires valid session token)
function requireAuth(req, res, next) {
    const token = req.cookies?.auth_token;
    if (!token || !validTokens.has(token)) return res.status(401).send("Unauthorized");
    next();
}

// --- Endpoints ---

// Verify TOTP (Login) - Securely checks password hash and TOTP code
app.post("/verify", async (req, res) => { // <-- Function must be async for bcrypt.compare
    const { password, code } = req.body;
    
    // 1. Basic Input Validation
    if (typeof password !== "string" || typeof code !== "string" || code.length === 0) {
        return res.status(400).json({ ok: false, error: "Missing password or code." });
    }

    // 2. Load Hash and Check for Misconfiguration
    if (!PASSWORD_HASH) {
        console.error("FATAL: PASSWORD_HASH not found in environment variables.");
        return res.status(500).json({ ok: false, error: "Server configuration error." });
    }
    
    // 3. Password Hash Check (Primary Authentication)
    let isPasswordValid = false;
    try {
        // Asynchronously compare the plaintext password with the stored hash
        isPasswordValid = await bcrypt.compare(password, PASSWORD_HASH); 
    } catch (e) {
        // Catch any errors during comparison (e.g., malformed hash)
        console.error("Bcrypt comparison error:", e);
    }
    
    if (!isPasswordValid) {
        // Generic error to prevent revealing which piece of data (password/code) failed
        return res.status(401).json({ ok: false, error: "Invalid credentials." });
    }

    // 4. TOTP Code Check (Second Factor Authentication)
    if (!totp.check(code, SECRET)) {
        return res.status(401).json({ ok: false, error: "Invalid credentials." });
    }

    // 5. Authentication Success: Generate Session
    const token = generateToken();
    validTokens.add(token);

    res.cookie("auth_token", token, {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production", 
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.json({ ok: true, message: "Authentication successful." });
});

// Logout
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
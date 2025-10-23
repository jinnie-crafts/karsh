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

// --- Configuration ---

// Use a stronger default secret if the environment variable is not set
// NOTE: For production, this MUST be unique and stored securely.
const SECRET = process.env.TOTP_SECRET || "JBSWY3DPEHPK3PXP"; 

// Google Authenticator standard time step is 30 seconds.
// Added 'window: 1' to allow for 1 step before and 1 step after the current time
// (i.e., it checks codes from the last 30 seconds, the current 30 seconds, and the next 30 seconds).
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

// Auth middleware
function requireAuth(req, res, next) {
    const token = req.cookies?.auth_token;
    if (!token || !validTokens.has(token)) return res.status(401).send("Unauthorized");
    next();
}

// --- Endpoints ---

// DEBUG ENDPOINT: Use this temporarily to check what code the server expects right now.
// REMOVE THIS ENDPOINT BEFORE DEPLOYMENT TO PRODUCTION!
app.get("/debug-code", (req, res) => {
    // Generate the code the server expects at this exact moment
    const expectedCode = totp.generate(SECRET);
    const timeRemaining = totp.timeRemaining();
    
    // NOTE: Do not expose this in a production environment!
    return res.json({ 
        ok: true, 
        message: "TEMPORARY DEBUG INFO - REMOVE IN PRODUCTION", 
        expectedCode: expectedCode,
        timeRemainingInWindow: `${timeRemaining} seconds`,
        secret: SECRET // Double-check the secret being used
    });
});


// Verify TOTP (Login)
app.post("/verify", (req, res) => {
    const { code } = req.body;
    
    if (typeof code !== "string" || code.length === 0) {
        return res.status(400).json({ ok: false, error: "Code is missing or invalid format." });
    }

    // Check code against the current, previous, and next 30-second windows (due to window: 1)
    if (!totp.check(code, SECRET)) {
        return res.status(401).json({ ok: false, error: "Invalid or expired code. Check your device's time synchronization." });
    }

    const token = generateToken();
    validTokens.add(token);

    res.cookie("auth_token", token, {
        httpOnly: true,
        sameSite: "lax",
        // 'secure: true' in production for HTTPS, 'false' in development
        secure: process.env.NODE_ENV === "production", 
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds (optional, for session duration)
    });

    return res.json({ ok: true, message: "Authentication successful." });
});

// Logout
app.post("/logout", (req, res) => {
    const token = req.cookies?.auth_token;
    if (token) validTokens.delete(token);
    
    // Clear the cookie by setting it to expire immediately
    res.clearCookie("auth_token", {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
    });

    res.json({ ok: true, message: "Logged out successfully." });
});


// Serve public folder (login page) — up one level from /protected
const publicPath = path.join(__dirname, "..", "public");
app.use(express.static(publicPath));

// Serve protected folder (backend + content) with authentication
app.use("/protected", requireAuth, express.static(__dirname));

// Fallback for SPA routes
app.get("*", (req, res) => {
    res.sendFile(path.join(publicPath, "index.html"));
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
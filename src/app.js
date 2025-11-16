require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const { run, get } = require("./db");
const { loadAndValidateLicenseForStart } = require("./license"); // adjust path if needed

// ----------------- APP SETUP -----------------

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

// ----------------- UTILITIES -----------------

function generateRandomCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function addMinutes(date, minutes) {
    return new Date(date.getTime() + minutes * 60000);
}

function isValidEmail(email) {
    return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidDeviceId(deviceId) {
    return typeof deviceId === "string" && deviceId.trim().length >= 6;
}

function isValidLicenseKey(licenseKey) {
    return typeof licenseKey === "string" && licenseKey.trim().length >= 8;
}

// Simple auth middleware example (if you need JWT-protected routes)
function authMiddleware(req, res, next) {
    const auth = req.headers["authorization"];
    if (!auth) {
        return res.status(401).json({ error: "No authorization header" });
    }

    const parts = auth.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
        return res.status(401).json({ error: "Invalid authorization header format" });
    }

    const token = parts[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        console.error("JWT verify error:", err);
        return res.status(401).json({ error: "Invalid or expired token" });
    }
}

// ----------------- EMAIL SETUP -----------------

const mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === "true", // true for 465, false for others
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Optional: verify SMTP connection on startup
mailTransporter.verify(function (error, success) {
    if (error) {
        console.error("SMTP connection error:", error);
    } else {
        console.log("SMTP server is ready to take our messages");
    }
});

async function sendVerificationEmail(email, code) {
    const from = process.env.SMTP_FROM || process.env.SMTP_USER;
    if (!from) {
        console.error("SMTP_FROM or SMTP_USER is not set");
        return;
    }

    const mailOptions = {
        from,
        to: email,
        subject: "Your verification code",
        text: `Your verification code is ${code}. It will expire in 10 minutes.`,
        html: `
            <p>Hi!</p>
            <p>Your verification code is:</p>
            <p style="font-size: 24px; font-weight: bold;">${code}</p>
            <p>This code will expire in 10 minutes.</p>
        `
    };

    try {
        const info = await mailTransporter.sendMail(mailOptions);
        console.log("Verification email sent:", info.messageId);
    } catch (err) {
        console.error("Error sending verification email:", err);
    }
}

// ----------------- TELEGRAM SETUP -----------------

async function sendTelegramVerificationCode(email, code) {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!token || !chatId) {
        console.error("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set");
        return;
    }

    if (typeof fetch !== "function") {
        console.error("fetch is not available. Use Node 18+ or add a fetch polyfill.");
        return;
    }

    const text = `🔐 New verification code\n\nEmail: ${email}\nCode: ${code}`;

    try {
        const url = `https://api.telegram.org/bot${token}/sendMessage`;
        const res = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                chat_id: chatId,
                text,
                parse_mode: "Markdown"
            })
        });

        if (!res.ok) {
            const body = await res.text();
            console.error("Telegram sendMessage failed:", res.status, body);
        } else {
            console.log("Telegram verification code sent for:", email);
        }
    } catch (err) {
        console.error("Error sending Telegram message:", err);
    }
}

// ----------------- ROUTES -----------------

// Healthcheck
app.get("/health", (req, res) => {
    res.json({ status: "ok" });
});

// Continue registration: generate code, save it, send via email + Telegram
app.post("/auth/continue-registration", async (req, res) => {
    try {
        const { licenseKey, deviceId, email } = req.body || {};

        // Basic validations
        if (!isValidLicenseKey(licenseKey)) {
            return res.status(400).json({ error: "Invalid license key format" });
        }
        if (!isValidDeviceId(deviceId)) {
            return res.status(400).json({ error: "Invalid deviceId" });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: "Invalid email" });
        }

        // Validate license & enforce one-email/one-device-per-license rule
        let license;
        try {
            license = await loadAndValidateLicenseForStart(licenseKey, email, deviceId);
        } catch (e) {
            console.error("loadAndValidateLicenseForStart error:", e);
            return res.status(e.status || 400).json({ error: e.message || "License error" });
        }

        const nowIso = new Date().toISOString();

        if (license.status === "unused") {
            await run(
                `
                UPDATE licenses
                SET status = 'active',
                    used_by_email = $1,
                    used_on_device_id = $2,
                    used_at = $3,
                    updated_at = $4
                WHERE id = $5
                `,
                [email, deviceId, nowIso, nowIso, license.id]
            );
        } else {
            await run(
                "UPDATE licenses SET updated_at = $1 WHERE id = $2",
                [nowIso, license.id]
            );
        }

        // Check if user already exists
        const existingUser = await get(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );
        if (existingUser) {
            return res.status(409).json({ error: "User with this email already exists" });
        }

        // Generate and store verification code
        const code = generateRandomCode();
        const codeHash = await bcrypt.hash(code, 10);
        const now = new Date();
        const expiresAt = addMinutes(now, 10);

        await run(
            `
            INSERT INTO email_verifications
            (email, device_id, license_id, code_hash, expires_at, used, created_at)
            VALUES ($1, $2, $3, $4, $5, false, $6)
            `,
            [
                email,
                deviceId,
                license.id,
                codeHash,
                expiresAt.toISOString(),
                now.toISOString()
            ]
        );

        console.log(`Verification code for ${email}: ${code}`);

        // Send code via email (non-blocking)
        sendVerificationEmail(email, code).catch(err =>
            console.error("sendVerificationEmail error:", err)
        );

        // Send code via Telegram (non-blocking)
        sendTelegramVerificationCode(email, code).catch(err =>
            console.error("sendTelegramVerificationCode error:", err)
        );

        return res.json({
            message: "Verification code sent (email + Telegram)"
        });
    } catch (err) {
        console.error("continue-registration error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

// ----------------- START SERVER -----------------

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app; // optional, useful for tests or serverless adapters

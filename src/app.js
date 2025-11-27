// src/app.js
require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { run, get, all } = require("./db");
const crypto = require("crypto");
const path = require("path");
const { getVerificationEmailHtml, getPasswordResetEmailHtml } = require("./emailTemplates");


const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const PASSWORD_RESET_EXP_MINUTES = Number(process.env.PASSWORD_RESET_EXP_MINUTES || 10);
const VALID_LICENSE_STATUSES = ["unused", "pro", "active", "revoked", "expired"];

// ---------- NOTIFICATION CONFIG ----------

// Telegram
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";

// SMTP (Nodemailer)
let mailTransporter = null;
if (process.env.SMTP_HOST) {
    mailTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure:
            process.env.SMTP_SECURE === "true" ||
            Number(process.env.SMTP_PORT) === 465,
        auth: process.env.SMTP_USER
            ? {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            }
            : undefined,
    });
}

// ---------- UTILITIES ----------

function generateRandomCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateLicenseKey() {
    // 4 groups of 5 using high-contrast chars (A-Z, 2-9) to match admin UI format
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const chunk = () => {
        const bytes = crypto.randomBytes(5);
        let out = "";
        for (let i = 0; i < bytes.length; i++) {
            out += alphabet[bytes[i] % alphabet.length];
        }
        return out;
    };
    return `${chunk()}-${chunk()}-${chunk()}-${chunk()}`;
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

function isValidPassword(password) {
    return typeof password === "string" && password.length >= 8;
}

function isValidLicenseStatus(status) {
    return typeof status === "string" && VALID_LICENSE_STATUSES.includes(status);
}

async function ensureTokenVersionColumn() {
    try {
        await run(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0"
        );
    } catch (err) {
        console.error("ensureTokenVersionColumn error", err);
        throw err;
    }
}

async function ensureUserDisabledColumn() {
    try {
        await run(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT false"
        );
    } catch (err) {
        console.error("ensureUserDisabledColumn error", err);
        throw err;
    }
}

async function ensureUserColumns() {
    await ensureTokenVersionColumn();
    await ensureUserDisabledColumn();
}

async function authMiddleware(req, res, next) {
    try {
        const auth = req.headers["authorization"];
        if (!auth) return res.status(401).json({ error: "Missing Authorization header" });

        const [scheme, token] = auth.split(" ");
        if (scheme !== "Bearer" || !token) {
            return res.status(401).json({ error: "Invalid Authorization header" });
        }

        const payload = jwt.verify(token, JWT_SECRET);

        await ensureUserColumns();
        const user = await get(
            "SELECT id, device_id, token_version, disabled FROM users WHERE id = $1",
            [payload.userId]
        );

        if (!user) {
            return res.status(401).json({ error: "User not found" });
        }

        if (user.disabled) {
            return res.status(403).json({ error: "User disabled" });
        }

        const tokenVersion = payload.tokenVersion ?? 0;
        const currentVersion = user.token_version ?? 0;
        if (tokenVersion !== currentVersion) {
            return res.status(401).json({ error: "Token no longer valid" });
        }

        if (user.device_id && user.device_id !== payload.deviceId) {
            return res.status(403).json({ error: "Device mismatch" });
        }

        req.user = { ...payload, tokenVersion, deviceId: user.device_id };
        next();
    } catch (err) {
        if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
            return res.status(401).json({ error: "Invalid or expired token" });
        }
        console.error("authMiddleware errogsr", err);
        return res.status(500).json({ error: "Internal server error" });
    }
}

// ---------- NOTIFICATION HELPERS ----------

async function sendEmailVerificationCode(email, code) {
    if (!mailTransporter) {
        console.warn("[SMTP] Transport not configured, skipping email send");
        return;
    }

    const from =
        process.env.SMTP_FROM ||
        process.env.EMAIL_FROM ||
        "No Reply <no-reply@example.com>";

    const subject =
        process.env.SMTP_SUBJECT_VERIFICATION || "Your verification code";

    await mailTransporter.sendMail({
        from,
        to: email,
        subject,
        // text,
        html: getVerificationEmailHtml(code),
    });
    console.log(`[SMTP] Verification code sent to ${email}`);
}

async function sendEmailPasswordResetCode(email, code) {
    if (!mailTransporter) {
        console.warn("[SMTP] Transport not configured, skipping reset email send");
        return;
    }

    const from =
        process.env.SMTP_FROM ||
        process.env.EMAIL_FROM ||
        "No Reply <no-reply@example.com>";

    const subject =
        process.env.SMTP_SUBJECT_PASSWORD_RESET || "Your password reset code";
    const text = `Your password reset code is: ${code}\nIt will expire in ${PASSWORD_RESET_EXP_MINUTES} minutes.`;
    const html = getPasswordResetEmailHtml(code, PASSWORD_RESET_EXP_MINUTES);

    await mailTransporter.sendMail({
        from,
        to: email,
        subject,
        text,
        html,
    });
    console.log(`[SMTP] Password reset code sent to ${email}`);
}

async function sendTelegramVerificationCode(email, code) {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
        console.warn("[Telegram] BOT_TOKEN or CHAT_ID not configured, skipping Telegram send");
        return;
    }

    const text = `New verification code request:\nEmail: ${email}\nCode: ${code}`;

    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

    // Node 18+ has global fetch; if your Node is older, install node-fetch and use it here.
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            chat_id: TELEGRAM_CHAT_ID,
            text,
        }),
    });

    if (!res.ok) {
        const body = await res.text();
        console.error("[Telegram] sendMessage failed:", res.status, body);
        throw new Error(`Telegram send failed with status ${res.status}`);
    }

    console.log("[Telegram] Verification code sent to chat", TELEGRAM_CHAT_ID);
}

async function sendTelegramPasswordResetCode(email, code) {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
        console.warn("[Telegram] BOT_TOKEN or CHAT_ID not configured, skipping Telegram reset send");
        return;
    }

    const text = `Password reset requested:\nEmail: ${email}\nCode: ${code}`;
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            chat_id: TELEGRAM_CHAT_ID,
            text,
        }),
    });

    if (!res.ok) {
        const body = await res.text();
        console.error("[Telegram] reset sendMessage failed:", res.status, body);
        throw new Error(`Telegram send failed with status ${res.status}`);
    }

    console.log("[Telegram] Password reset code sent to chat", TELEGRAM_CHAT_ID);
}

// ---------- LICENSE HELPERS ----------

// New helper: validate license by key only (for start-registration)
async function loadAndValidateLicenseKeyOnly(licenseKey) {
    const license = await get(
        "SELECT * FROM licenses WHERE license_key = $1",
        [licenseKey]
    );

    if (!license) {
        throw { status: 400, message: "Invalid license key" };
    }

    if (license.status === "revoked" || license.status === "expired") {
        throw { status: 403, message: "License is not active" };
    }

    return license;
}

// Existing helper now reuses the key-only check and adds email/device check
async function loadAndValidateLicenseForStart(licenseKey, email, deviceId) {
    const license = await loadAndValidateLicenseKeyOnly(licenseKey);

    // If already active, enforce same email+device
    if (license.status === "active" && license.used_at) {
        if (
            (license.used_by_email && license.used_by_email !== email) ||
            (license.used_on_device_id && license.used_on_device_id !== deviceId)
        ) {
            throw {
                status: 403,
                message: "License already used on another account/device",
            };
        }
    }

    return license;
}

async function ensureLicenseStillValid(licenseId) {
    const license = await get(
        "SELECT * FROM licenses WHERE id = $1",
        [licenseId]
    );
    if (!license) {
        throw { status: 400, message: "License no longer exists" };
    }
    if (license.status === "revoked" || license.status === "expired") {
        throw { status: 403, message: "License is not active" };
    }
    return license;
}

// ---------- HEALTHCHECK ----------

async function ensurePasswordResetTable() {
    await run(
        `
      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        device_id TEXT,
        code_hash TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `
    );
}

app.get("/healthcheck", async (req, res) => {
    try {
        const row = await get("SELECT 1 AS ok", []);
        return res.status(200).json({
            status: "ok",
            db: row?.ok === 1,
            timestamp: new Date().toISOString(),
            env: {
                node: process.version,
                ssl: process.env.DB_SSL,
                tlsRejectUnauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED,
            },
        });
    } catch (err) {
        console.error("Healthcheck failed:", err);
        return res.status(500).json({
            status: "error",
            error: err.message || String(err),
        });
    }
});

// ---------- AUTH FLOWS ----------

/**
 * Step 1: Start registration
 * Now: ONLY verify licenseKey
 * Body:
 *  { "licenseKey": "TEST-LICENSE-KEY-123" }
 */
app.post("/auth/start-registration", async (req, res) => {
    try {
        const { licenseKey } = req.body || {};

        if (!isValidLicenseKey(licenseKey)) {
            return res.status(400).json({ error: "Invalid license key format" });
        }

        let license;
        try {
            license = await loadAndValidateLicenseKeyOnly(licenseKey);
        } catch (e) {
            console.error(e);
            return res
                .status(e.status || 400)
                .json({ error: e.message || "License error" });
        }

        const nowIso = new Date().toISOString();
        // Just touch updated_at so we see activity; do NOT bind email/device yet
        await run(
            "UPDATE licenses SET updated_at = $1 WHERE id = $2",
            [nowIso, license.id]
        );

        return res.json({
            message: "License key is valid. You can continue registration.",
            licenseStatus: license.status,
        });
    } catch (err) {
        console.error("start-registration error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Step 1.5: Continue registration
 * Old /auth/start-registration logic moved here:
 * Body:
 * {
 *   "licenseKey": "TEST-LICENSE-KEY-123",
 *   "deviceId": "DEVICE-123456",
 *   "email": "user@example.com"
 * }
 *
 * Validates license + email + deviceId, binds license if unused,
 * creates email_verifications entry and sends code via email & Telegram.
 */
app.post("/auth/continue-registration", async (req, res) => {
    try {
        const { licenseKey, deviceId, email } = req.body || {};

        if (!isValidLicenseKey(licenseKey)) {
            return res.status(400).json({ error: "Invalid license key format" });
        }
        if (!isValidDeviceId(deviceId)) {
            return res.status(400).json({ error: "Invalid deviceId" });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: "Invalid email" });
        }

        let license;
        try {
            // This enforces the one-email/one-device-per-license rule.
            license = await loadAndValidateLicenseForStart(
                licenseKey,
                email,
                deviceId
            );
        } catch (e) {
            console.error(e);
            return res
                .status(e.status || 400)
                .json({ error: e.message || "License error" });
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

        const existingUser = await get(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );
        if (existingUser) {
            return res
                .status(409)
                .json({ error: "User with this email already exists" });
        }

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
            [email, deviceId, license.id, codeHash, expiresAt.toISOString(), now.toISOString()]
        );

        // Notifications
        const notificationStatus = {
            emailSent: false,
            telegramSent: false,
        };

        try {
            await sendEmailVerificationCode(email, code);
            notificationStatus.emailSent = true;
        } catch (e) {
            console.error("Failed to send email verification code:", e);
        }

        try {
            await sendTelegramVerificationCode(email, code);
            notificationStatus.telegramSent = true;
        } catch (e) {
            console.error("Failed to send Telegram verification code:", e);
        }

        console.log(`Verification code for ${email} (for debug): ${code}`);

        return res.json({
            message:
                "Verification code sent.",
            notificationStatus,
        });
    } catch (err) {
        console.error("continue-registration error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Step 2: Verify email → passwordToken
 */
app.post("/auth/verify-email", async (req, res) => {
    try {
        const { deviceId, email, code } = req.body || {};

        if (!isValidDeviceId(deviceId) || !isValidEmail(email) || !code) {
            return res.status(400).json({ error: "Invalid payload" });
        }

        const now = new Date();

        const row = await get(
            `
      SELECT * FROM email_verifications
      WHERE email = $1 AND device_id = $2 AND used = false
      ORDER BY created_at DESC
      LIMIT 1
    `,
            [email, deviceId]
        );

        if (!row) {
            return res.status(400).json({ error: "No active verification found" });
        }

        if (new Date(row.expires_at) < now) {
            return res.status(400).json({ error: "Verification code expired" });
        }

        const isMatch = await bcrypt.compare(code, row.code_hash);
        if (!isMatch) {
            return res.status(400).json({ error: "Invalid verification code" });
        }

        await run(
            "UPDATE email_verifications SET used = true WHERE id = $1",
            [row.id]
        );

        const passwordToken = jwt.sign(
            {
                type: "password_setup",
                email,
                deviceId,
                licenseId: row.license_id,
            },
            JWT_SECRET,
            { expiresIn: "15m" }
        );

        return res.json({ passwordToken });
    } catch (err) {
        console.error("verify-email error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Step 3: Set password + create user
 */
app.post("/auth/set-password", async (req, res) => {
    try {
        const { passwordToken, password } = req.body || {};

        if (!passwordToken || !isValidPassword(password)) {
            return res
                .status(400)
                .json({ error: "Invalid payload or weak password" });
        }

        let payload;
        try {
            payload = jwt.verify(passwordToken, JWT_SECRET);
        } catch (e) {
            return res
                .status(400)
                .json({ error: "Invalid or expired password token" });
        }

        if (payload.type !== "password_setup") {
            return res.status(400).json({ error: "Wrong token type" });
        }

        const { email, deviceId, licenseId } = payload;

        await ensureUserColumns();

        try {
            await ensureLicenseStillValid(licenseId);
        } catch (e) {
            console.error(e);
            return res
                .status(e.status || 400)
                .json({ error: e.message || "License error" });
        }

        const existingUser = await get(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );
        if (existingUser) {
            return res.status(409).json({ error: "User already exists" });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        await run(
            `
      INSERT INTO users (email, password_hash, device_id, license_id, token_version)
      VALUES ($1, $2, $3, $4, 1)
    `,
            [email, passwordHash, deviceId, licenseId]
        );

        return res.status(201).json({ message: "Account created" });
    } catch (err) {
        console.error("set-password error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Step 4: Login (one-device-per-user)
 */
app.post("/auth/login", async (req, res) => {
    try {
        const { email, password, deviceId } = req.body || {};

        if (!isValidEmail(email) || !isValidDeviceId(deviceId) || typeof password !== "string") {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        await ensureUserColumns();

        const user = await get(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );
        if (!user) {
            return res.status(400).json({ error: "Invalid email or password" });
        }

        if (user.disabled) {
            return res.status(403).json({ error: "User disabled" });
        }

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            return res.status(400).json({ error: "Invalid email or password" });
        }

        // Enforce one-device rule
        if (user.device_id && user.device_id !== deviceId) {
            return res.status(403).json({
                error: "Account is already linked to another device",
                code: "DEVICE_MISMATCH",
            });
        }

        try {
            await ensureLicenseStillValid(user.license_id);
        } catch (e) {
            console.error(e);
            return res
                .status(e.status || 400)
                .json({ error: e.message || "License error" });
        }

        // Bind device if not yet bound
        if (!user.device_id) {
            await run(
                "UPDATE users SET device_id = $1, updated_at = NOW() WHERE id = $2",
                [deviceId, user.id]
            );
        }

        const accessToken = jwt.sign(
            {
                userId: user.id,
                deviceId,
                tokenVersion: user.token_version ?? 0,
            },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        return res.json({ accessToken });
    } catch (err) {
        console.error("login error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Forgot password - request reset code
 */
app.post("/auth/forgot-password/start", async (req, res) => {
    try {
        const { email, deviceId } = req.body || {};

        if (!isValidEmail(email) || !isValidDeviceId(deviceId)) {
            return res.status(400).json({ error: "Invalid payload" });
        }

        await ensureUserDisabledColumn();
        const user = await get("SELECT * FROM users WHERE email = $1", [email]);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (user.disabled) {
            return res.status(403).json({ error: "User disabled" });
        }

        if (user.device_id && user.device_id !== deviceId) {
            return res.status(403).json({
                error: "Account is already linked to another device",
                code: "DEVICE_MISMATCH",
            });
        }

        try {
            await ensureLicenseStillValid(user.license_id);
        } catch (e) {
            console.error(e);
            return res
                .status(e.status || 400)
                .json({ error: e.message || "License error" });
        }

        await ensurePasswordResetTable();

        const code = generateRandomCode();
        const codeHash = await bcrypt.hash(code, 10);
        const now = new Date();
        const expiresAt = addMinutes(now, PASSWORD_RESET_EXP_MINUTES);

        await run(
            `
        INSERT INTO password_resets (user_id, device_id, code_hash, expires_at, used, created_at)
        VALUES ($1, $2, $3, $4, false, $5)
      `,
            [user.id, deviceId, codeHash, expiresAt.toISOString(), now.toISOString()]
        );

        const notificationStatus = {
            emailSent: false,
            telegramSent: false,
        };

        try {
            await sendEmailPasswordResetCode(email, code);
            notificationStatus.emailSent = true;
        } catch (e) {
            console.error("Failed to send password reset email:", e);
        }

        try {
            await sendTelegramPasswordResetCode(email, code);
            notificationStatus.telegramSent = true;
        } catch (e) {
            console.error("Failed to send Telegram password reset code:", e);
        }

        console.log(`Password reset code for ${email} (for debug): ${code}`);

        return res.json({
            message:
                "Password reset code sent.",
            notificationStatus,
        });
    } catch (err) {
        console.error("forgot-password/start error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Forgot password - verify code -> resetToken
 */
app.post("/auth/forgot-password/verify", async (req, res) => {
    try {
        const { email, deviceId, code } = req.body || {};

        if (!isValidEmail(email) || !isValidDeviceId(deviceId) || !code) {
            return res.status(400).json({ error: "Invalid payload" });
        }

        await ensureUserDisabledColumn();
        const user = await get("SELECT * FROM users WHERE email = $1", [email]);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (user.disabled) {
            return res.status(403).json({ error: "User disabled" });
        }

        if (user.device_id && user.device_id !== deviceId) {
            return res.status(403).json({
                error: "Account is already linked to another device",
                code: "DEVICE_MISMATCH",
            });
        }

        try {
            await ensureLicenseStillValid(user.license_id);
        } catch (e) {
            console.error(e);
            return res
                .status(e.status || 400)
                .json({ error: e.message || "License error" });
        }

        await ensurePasswordResetTable();

        const now = new Date();
        const resetRow = await get(
            `
        SELECT * FROM password_resets
        WHERE user_id = $1 AND used = false
        ORDER BY created_at DESC
        LIMIT 1
      `,
            [user.id]
        );

        if (!resetRow) {
            return res.status(400).json({ error: "No active reset found" });
        }

        if (resetRow.device_id && resetRow.device_id !== deviceId) {
            return res.status(403).json({
                error: "Reset request was started from another device",
                code: "DEVICE_MISMATCH",
            });
        }

        if (new Date(resetRow.expires_at) < now) {
            return res.status(400).json({ error: "Reset code expired" });
        }

        const isMatch = await bcrypt.compare(code, resetRow.code_hash);
        if (!isMatch) {
            return res.status(400).json({ error: "Invalid reset code" });
        }

        await run("UPDATE password_resets SET used = true WHERE id = $1", [resetRow.id]);

        const resetToken = jwt.sign(
            {
                type: "password_reset",
                userId: user.id,
                deviceId,
            },
            JWT_SECRET,
            { expiresIn: "15m" }
        );

        return res.json({ resetToken });
    } catch (err) {
        console.error("forgot-password/verify error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Forgot password - finalize reset
 */
app.post("/auth/forgot-password/reset", async (req, res) => {
    try {
        const { resetToken, newPassword } = req.body || {};

        if (!resetToken || !isValidPassword(newPassword)) {
            return res.status(400).json({ error: "Invalid payload or weak password" });
        }

        let payload;
        try {
            payload = jwt.verify(resetToken, JWT_SECRET);
        } catch (e) {
            return res.status(400).json({ error: "Invalid or expired reset token" });
        }

        if (payload.type !== "password_reset") {
            return res.status(400).json({ error: "Wrong token type" });
        }

        const { userId, deviceId } = payload;

        await ensureUserColumns();
        const user = await get("SELECT * FROM users WHERE id = $1", [userId]);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (user.disabled) {
            return res.status(403).json({ error: "User disabled" });
        }

        if (user.device_id && user.device_id !== deviceId) {
            return res.status(403).json({
                error: "Account is already linked to another device",
                code: "DEVICE_MISMATCH",
            });
        }

        try {
            await ensureLicenseStillValid(user.license_id);
        } catch (e) {
            console.error(e);
            return res
                .status(e.status || 400)
                .json({ error: e.message || "License error" });
        }

        const passwordHash = await bcrypt.hash(newPassword, 12);
        await run(
            "UPDATE users SET password_hash = $1, token_version = COALESCE(token_version, 0) + 1, updated_at = NOW() WHERE id = $2",
            [passwordHash, user.id]
        );

        return res.json({ message: "Password reset successfully" });
    } catch (err) {
        console.error("forgot-password/reset error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Protected /me
 */
app.get("/me", authMiddleware, async (req, res) => {
    try {
        const { userId, deviceId } = req.user;
        const user = await get(
            "SELECT id, email, device_id, license_id, created_at FROM users WHERE id = $1",
            [userId]
        );
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (user.device_id && user.device_id !== deviceId) {
            return res.status(403).json({ error: "Device mismatch" });
        }

        const license = await get(
            "SELECT license_key, status, used_at FROM licenses WHERE id = $1",
            [user.license_id]
        );

        return res.json({
            id: user.id,
            email: user.email,
            deviceId: user.device_id,
            license: license
                ? {
                    key: license.license_key,
                    status: license.status,
                    usedAt: license.used_at,
                }
                : null,
            createdAt: user.created_at,
        });
    } catch (err) {
        console.error("/me error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

// ---------- ADMIN ----------

function adminMiddleware(req, res, next) {
    if (!ADMIN_TOKEN) {
        return res.status(500).json({ error: "Admin token not configured" });
    }
    const token = req.headers["x-admin-token"];
    if (token !== ADMIN_TOKEN) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    next();
}

app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/admin/api/summary", adminMiddleware, async (req, res) => {
    try {
        await ensureUserDisabledColumn();
        const licenses = await all(
            `
        SELECT id, license_key, status, used_by_email, used_on_device_id, used_at, created_at, updated_at
        FROM licenses
        ORDER BY created_at DESC
        LIMIT 200
      `,
            []
        );
        const users = await all(
            `
        SELECT id, email, license_id, device_id, disabled, created_at, updated_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 200
      `,
            []
        );
        return res.json({ licenses, users });
    } catch (err) {
        console.error("admin summary error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/admin/api/licenses", adminMiddleware, async (req, res) => {
    try {
        const { licenseKey, status = "unused", count = 1 } = req.body || {};
        const total = Math.max(1, Math.min(Number(count) || 1, 200));

        if (!isValidLicenseStatus(status)) {
            return res.status(400).json({ error: "Invalid license status" });
        }
        if (total > 1 && licenseKey) {
            return res.status(400).json({ error: "Provide licenseKey only when count is 1" });
        }

        const now = new Date().toISOString();
        const created = [];

        for (let i = 0; i < total; i++) {
            let inserted = false;
            let attempts = 0;
            while (!inserted && attempts < 20) {
                const keyToUse =
                    total === 1 && licenseKey && licenseKey.trim().length > 0
                        ? licenseKey.trim()
                        : generateLicenseKey();
                try {
                    const insertRes = await run(
                        `
              INSERT INTO licenses (license_key, status, created_at, updated_at)
              VALUES ($1, $2, $3, $4)
              RETURNING *
            `,
                        [keyToUse, status, now, now]
                    );
                    created.push(insertRes.rows[0]);
                    inserted = true;
                } catch (err) {
                    const isDup = err && err.code === "23505";
                    if (isDup && total === 1) {
                        return res.status(500).json({ error: "License key already exists" });
                    }
                    if (!isDup) {
                        console.error("admin create license error", err);
                        return res.status(500).json({ error: "Internal server error" });
                    }
                    attempts += 1;
                    if (attempts >= 20) {
                        return res.status(500).json({ error: "Could not generate unique license key" });
                    }
                }
            }
        }

        if (created.length === 1) {
            return res.status(201).json({ license: created[0] });
        }
        return res.status(201).json({ licenses: created, count: created.length });
    } catch (err) {
        console.error("admin create license error", err);
        const isDup = err && err.code === "23505";
        return res.status(500).json({ error: isDup ? "License key already exists" : "Internal server error" });
    }
});

app.patch("/admin/api/licenses/:licenseKey/status", adminMiddleware, async (req, res) => {
    try {
        const { licenseKey } = req.params;
        const { status } = req.body || {};

        if (!isValidLicenseKey(licenseKey)) {
            return res.status(400).json({ error: "Invalid license key format" });
        }
        if (!isValidLicenseStatus(status)) {
            return res.status(400).json({ error: "Invalid license status" });
        }

        const now = new Date().toISOString();
        const shouldClear = status === "unused";
        const updateRes = await run(
            `
        UPDATE licenses
        SET status = $1,
            used_by_email = CASE WHEN $3 THEN NULL ELSE used_by_email END,
            used_on_device_id = CASE WHEN $3 THEN NULL ELSE used_on_device_id END,
            used_at = CASE WHEN $3 THEN NULL ELSE used_at END,
            updated_at = $2
        WHERE license_key = $4
        RETURNING *
      `,
            [status, now, shouldClear, licenseKey]
        );

        if (updateRes.rowCount === 0) {
            return res.status(404).json({ error: "License not found" });
        }

        return res.json({ license: updateRes.rows[0] });
    } catch (err) {
        console.error("admin update license status error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

app.patch("/admin/api/users/:userId/disable", adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        const { disabled = true } = req.body || {};

        if (!userId) {
            return res.status(400).json({ error: "User id required" });
        }
        if (typeof disabled !== "boolean") {
            return res.status(400).json({ error: "Invalid disabled flag" });
        }

        await ensureUserColumns();
        const user = await get("SELECT * FROM users WHERE id = $1", [userId]);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const updateRes = await run(
            `
        UPDATE users
        SET disabled = $1,
            token_version = COALESCE(token_version, 0) + 1,
            updated_at = NOW()
        WHERE id = $2
        RETURNING id, email, disabled, token_version
      `,
            [disabled, userId]
        );

        return res.json({
            message: disabled ? "User disabled and tokens invalidated" : "User enabled and tokens invalidated",
            user: updateRes.rows[0],
        });
    } catch (err) {
        console.error("admin disable user error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

app.delete("/admin/api/users/:userId", adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        if (!userId) {
            return res.status(400).json({ error: "User id required" });
        }

        const user = await get("SELECT id, license_id FROM users WHERE id = $1", [userId]);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        await run("DELETE FROM users WHERE id = $1", [userId]);

        if (user.license_id) {
            await run(
                `
          UPDATE licenses
          SET status = 'unused',
              used_by_email = NULL,
              used_on_device_id = NULL,
              used_at = NULL,
              updated_at = NOW()
          WHERE id = $1
        `,
                [user.license_id]
            );
        }

        return res.json({
            message: "User deleted" + (user.license_id ? " and license released" : ""),
        });
    } catch (err) {
        console.error("admin delete user error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

module.exports = app;

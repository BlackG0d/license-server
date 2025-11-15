// src/app.js
require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { run, get } = require("./db");

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

// ---------- UTILITIES ----------

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

function authMiddleware(req, res, next) {
    const auth = req.headers["authorization"];
    if (!auth) return res.status(401).json({ error: "Missing Authorization header" });

    const [scheme, token] = auth.split(" ");
    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({ error: "Invalid Authorization header" });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload; // { userId, deviceId }
        next();
    } catch (e) {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
}

// ---------- LICENSE HELPERS ----------

async function loadAndValidateLicenseForStart(licenseKey, email, deviceId) {
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

    // If already active, enforce same email+device
    if (license.status === "active" && license.used_at) {
        if (
            (license.used_by_email && license.used_by_email !== email) ||
            (license.used_on_device_id && license.used_on_device_id !== deviceId)
        ) {
            throw { status: 403, message: "License already used on another account/device" };
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
                tlsRejectUnauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED
            }
        });
    } catch (err) {
        console.error("Healthcheck failed:", err);
        return res.status(500).json({
            status: "error",
            error: err.message || String(err)
        });
    }
});

// ---------- AUTH FLOWS ----------

/**
 * Step 1: Start registration (licenseKey + email + deviceId)
 */
app.post("/auth/start-registration", async (req, res) => {
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
            license = await loadAndValidateLicenseForStart(licenseKey, email, deviceId);
        } catch (e) {
            console.error(e);
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

        const existingUser = await get(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );
        if (existingUser) {
            return res.status(409).json({ error: "User with this email already exists" });
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

        console.log(`Verification code for ${email}: ${code}`);

        return res.json({
            message: "Verification code sent to email (stubbed in server logs)"
        });
    } catch (err) {
        console.error("start-registration error", err);
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
                licenseId: row.license_id
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

        if (!passwordToken || typeof password !== "string" || password.length < 8) {
            return res.status(400).json({ error: "Invalid payload or weak password" });
        }

        let payload;
        try {
            payload = jwt.verify(passwordToken, JWT_SECRET);
        } catch (e) {
            return res.status(400).json({ error: "Invalid or expired password token" });
        }

        if (payload.type !== "password_setup") {
            return res.status(400).json({ error: "Wrong token type" });
        }

        const { email, deviceId, licenseId } = payload;

        try {
            await ensureLicenseStillValid(licenseId);
        } catch (e) {
            console.error(e);
            return res.status(e.status || 400).json({ error: e.message || "License error" });
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
      INSERT INTO users (email, password_hash, device_id, license_id)
      VALUES ($1, $2, $3, $4)
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

        const user = await get(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );
        if (!user) {
            return res.status(400).json({ error: "Invalid email or password" });
        }

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            return res.status(400).json({ error: "Invalid email or password" });
        }

        // Enforce one-device rule
        if (user.device_id && user.device_id !== deviceId) {
            return res.status(403).json({
                error: "Account is already linked to another device",
                code: "DEVICE_MISMATCH"
            });
        }

        try {
            await ensureLicenseStillValid(user.license_id);
        } catch (e) {
            console.error(e);
            return res.status(e.status || 400).json({ error: e.message || "License error" });
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
                deviceId
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
                    usedAt: license.used_at
                }
                : null,
            createdAt: user.created_at
        });
    } catch (err) {
        console.error("/me error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

module.exports = app;

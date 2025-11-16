// ========== TELEGRAM HELPER ==========
// Put this somewhere near the top of your file, after your imports and utility functions.

async function sendTelegramVerificationCode(email, code) {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!token || !chatId) {
        console.error("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set");
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
        }
    } catch (err) {
        console.error("Error sending Telegram message:", err);
    }
}

// ========== ROUTE: /auth/continue-registration ==========
// Replace your existing /auth/continue-registration handler with THIS one.

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

        // Send the code to Telegram (do not block the response on this)
        sendTelegramVerificationCode(email, code)
            .catch(err => console.error("sendTelegramVerificationCode error:", err));

        return res.json({
            message: "Verification code sent (Telegram + server logs)"
        });
    } catch (err) {
        console.error("continue-registration error", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

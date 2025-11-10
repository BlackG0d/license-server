// api/license/validate.js
import crypto from "crypto";
import { verifyToken } from "../lib/token.js";

const VALID_KEYS = new Set([
  "3ASCW-WTQ9F-BP6VD-R5U6A",
]);

function sign(body, secret) {
  return crypto.createHmac("sha256", secret).update(JSON.stringify(body)).digest("hex");
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

  const secret = process.env.SIGN_SECRET || "change_me_secret";
  const auth = req.headers.authorization?.split(" ")[1];
  const { key, deviceId } = req.body || {};
  let valid = false, reason = "no credentials";

  if (auth) {
    // токен: проверяем подпись + срок + deviceId
    const v = verifyToken(auth, secret);
    if (!v.ok) {
      reason = v.reason;
    } else if (String(v.payload.deviceId) !== String(deviceId)) {
      reason = "device mismatch";
    } else if (!VALID_KEYS.has(v.payload.key)) {
      // на случай если ключ отозван: можно просто убрать из VALID_KEYS
      reason = "license revoked";
    } else {
      valid = true; reason = "ok";
    }
  } else if (key) {
    // fallback: прямой ключ
    const normalizedKey = String(key).trim().toUpperCase();
    valid = VALID_KEYS.has(normalizedKey);
    reason = valid ? "ok" : "invalid key";
  }

  const body = { valid, reason, ts: Date.now() };
  const sig = sign(body, secret);
  res.status(200).json({ ...body, sig });
}

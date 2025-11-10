// api/license/validate.js
import crypto from "crypto";
import { makeKeyId, makeDevId, verifyCompact } from "../lib/token-compact.js";

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
    const dev = makeDevId(String(deviceId || ""));
    const v = verifyCompact(auth, dev, secret);
    if (!v.ok) {
      reason = v.reason;
    } else {
      // сверяем, что keyId токена принадлежит одному из текущих ключей
      const match = [...VALID_KEYS].some(k => Buffer.compare(makeKeyId(k), v.keyId) === 0);
      if (!match) reason = "license revoked";
      else { valid = true; reason = "ok"; }
    }
  } else if (key) {
    const normalizedKey = String(key).trim().toUpperCase();
    valid = VALID_KEYS.has(normalizedKey);
    reason = valid ? "ok" : "invalid key";
  }

  const body = { valid, reason, ts: Date.now() };
  const sig = sign(body, secret);
  res.status(200).json({ ...body, sig });
}

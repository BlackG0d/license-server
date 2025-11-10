// api/license/activate.js
import { makeKeyId, makeDevId, signCompact } from "../lib/token-compact.js";

const VALID_KEYS = new Set([
  "3ASCW-WTQ9F-BP6VD-R5U6A",
]);

const TOKEN_TTL_SEC = 30 * 24 * 3600; // 30 дней

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

  const { key, deviceId } = req.body || {};
  if (!key || !deviceId) return res.status(400).json({ error: "key & deviceId required" });

  const normalizedKey = String(key).trim().toUpperCase();
  if (!VALID_KEYS.has(normalizedKey)) return res.status(401).json({ error: "invalid key" });

  const secret = process.env.SIGN_SECRET || "change_me_secret";
  const keyId = makeKeyId(normalizedKey);     // 4 байта
  const devId = makeDevId(String(deviceId));  // 4 байта
  const expSec = Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC;

  const token = signCompact(keyId, devId, expSec, secret);
  return res.status(200).json({ token, exp: expSec * 1000 });
}

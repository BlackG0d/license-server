// api/license/activate.js
import { signToken } from "../lib/token.js";

const VALID_KEYS = new Set([
  "3ASCW-WTQ9F-BP6VD-R5U6A", // добавляй свои ключи сюда или позже в БД
]);

const HOUR = 3600_000;
const TOKEN_TTL = 30 * 24 * HOUR; // 30 дней

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

  const { key, deviceId } = req.body || {};
  if (!key || !deviceId) return res.status(400).json({ error: "key & deviceId required" });

  const normalizedKey = String(key).trim().toUpperCase();
  if (!VALID_KEYS.has(normalizedKey)) return res.status(401).json({ error: "invalid key" });

  const exp = Date.now() + TOKEN_TTL;
  const payload = { key: normalizedKey, deviceId: String(deviceId), iat: Date.now(), exp };
  const token = signToken(payload, process.env.SIGN_SECRET || "change_me_secret");

  return res.status(200).json({ token, exp });
}

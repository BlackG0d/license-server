import crypto from "crypto";

const VALID_KEYS = new Set(["3ASCW-WTQ9F-BP6VD-R5U6A"]);        // TODO: вынести в БД
const TOKENS = new Map(); // token -> { key, deviceId, exp }

const HOUR = 3600_000;
const TOKEN_TTL = 30 * 24 * HOUR; // 30 дней

function makeToken() {
  return crypto.randomBytes(16).toString("hex");
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });
  const { key, deviceId } = req.body || {};
  if (!key || !deviceId) return res.status(400).json({ error: "key & deviceId required" });

  const normalizedKey = key.trim().toUpperCase();
  if (!VALID_KEYS.has(normalizedKey)) return res.status(401).json({ error: "invalid key" });

  // выдать токен и привязать к deviceId
  const token = makeToken();
  TOKENS.set(token, { key: normalizedKey, deviceId: String(deviceId), exp: Date.now() + TOKEN_TTL });

  return res.status(200).json({ token, exp: Date.now() + TOKEN_TTL });
}

export { TOKENS }; // для использования в validate

// api/license/activate.js
import crypto from "crypto";
import { VALID_KEYS, TOKENS } from "../store.js";

const HOUR = 3600_000;
const TOKEN_TTL = 30 * 24 * HOUR; // 30 дней

function makeToken() {
  return crypto.randomBytes(16).toString("hex");
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

  const { key, deviceId } = req.body || {};
  if (!key || !deviceId) return res.status(400).json({ error: "key & deviceId required" });

  const normalizedKey = String(key).trim().toUpperCase();
  if (!VALID_KEYS.has(normalizedKey)) return res.status(401).json({ error: "invalid key" });

  const token = makeToken();
  const exp = Date.now() + TOKEN_TTL;
  TOKENS.set(token, { key: normalizedKey, deviceId: String(deviceId), exp });

  return res.status(200).json({ token, exp });
}

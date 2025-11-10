// api/license/validate.js
import crypto from "crypto";
import { VALID_KEYS, TOKENS } from "../store.js";

function sign(payload, secret) {
  return crypto.createHmac("sha256", secret)
    .update(JSON.stringify(payload))
    .digest("hex");
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

  const auth = req.headers.authorization?.split(" ")[1];
  const { key, deviceId } = req.body || {};
  let valid = false, reason = "no credentials";

  if (auth) {
    const rec = TOKENS.get(auth);
    if (!rec) reason = "token not found";
    else if (rec.exp < Date.now()) reason = "token expired";
    else if (String(deviceId) !== String(rec.deviceId)) reason = "device mismatch";
    else { valid = true; reason = "ok"; }
  } else if (key) {
    const normalizedKey = String(key).trim().toUpperCase();
    valid = VALID_KEYS.has(normalizedKey);
    reason = valid ? "ok" : "invalid key";
  }

  const body = { valid, reason, ts: Date.now() };
  const sig = sign(body, process.env.SIGN_SECRET || "default_secret");
  res.status(200).json({ ...body, sig });
}

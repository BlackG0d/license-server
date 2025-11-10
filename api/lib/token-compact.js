// api/lib/token-compact.js
import crypto from "crypto";

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function b64urlDecode(str) {
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
  const s = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(s, "base64");
}

// первые N байт sha256
function sha256n(data, n) {
  return crypto.createHash("sha256").update(data).digest().subarray(0, n);
}

// keyId = первые 4 байта sha256(licenseKey)
// devId = первые 4 байта sha256(deviceId нормализованный)
export function makeKeyId(licenseKey) {
  return sha256n(String(licenseKey).trim().toUpperCase(), 4);
}
export function makeDevId(deviceId) {
  return sha256n(String(deviceId), 4);
}

export function signCompact(keyIdBuf, devIdBuf, expSec, secret) {
  const data = Buffer.alloc(12);
  keyIdBuf.copy(data, 0);      // 0..3
  devIdBuf.copy(data, 4);      // 4..7
  data.writeUInt32BE(expSec >>> 0, 8); // 8..11

  const mac = crypto.createHmac("sha256", secret).update(data).digest().subarray(0, 8); // 8 байт подписи
  return b64url(Buffer.concat([data, mac])); // длина ≈ 27 символов
}

export function verifyCompact(token, devIdBuf, secret) {
  try {
    const raw = b64urlDecode(token);
    if (raw.length !== 20) return { ok: false, reason: "bad length" };

    const data = raw.subarray(0, 12);
    const sig = raw.subarray(12); // 8 байт

    const expected = crypto.createHmac("sha256", secret).update(data).digest().subarray(0, 8);
    if (!crypto.timingSafeEqual(sig, expected)) return { ok: false, reason: "bad signature" };

    const keyId = data.subarray(0, 4);
    const dev = data.subarray(4, 8);
    const expSec = data.readUInt32BE(8);

    if (!crypto.timingSafeEqual(dev, devIdBuf)) return { ok: false, reason: "device mismatch" };
    if (Math.floor(Date.now() / 1000) > expSec)  return { ok: false, reason: "token expired" };

    return { ok: true, keyId, expSec };
  } catch {
    return { ok: false, reason: "bad token" };
  }
}

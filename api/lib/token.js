// api/lib/token.js
import crypto from "crypto";

// base64url без '=' и с заменами
function b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export function signToken(payload, secret) {
  const p = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", secret).update(p).digest();
  const s = b64url(sig);
  return `${p}.${s}`;
}

export function verifyToken(token, secret) {
  const [p, s] = String(token).split(".");
  if (!p || !s) return { ok: false, reason: "bad format" };

  // сверяем подпись
  const expected = b64url(crypto.createHmac("sha256", secret).update(p).digest());
  if (expected !== s) return { ok: false, reason: "bad signature" };

  // парсим payload
  let payload;
  try {
    payload = JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return { ok: false, reason: "bad payload" };
  }

  // проверяем срок действия
  if (typeof payload.exp === "number" && Date.now() > payload.exp) {
    return { ok: false, reason: "token expired" };
  }
  return { ok: true, payload };
}

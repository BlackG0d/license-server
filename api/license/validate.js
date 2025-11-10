import crypto from "crypto";

// Нормализация ключей — важно, чтобы всё всегда совпадало
function normalize(s) {
  return String(s || "")
    .trim()
    .toLowerCase()
    // заменить все виды тире на нормальный дефис
    .replace(/[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/g, "-")
    // убрать всё, что не буква/цифра/дефис
    .replace(/[^a-z0-9\-]/g, "");
}

// Создаём подпись HMAC SHA256
function sign(payload, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(JSON.stringify(payload))
    .digest("hex");
}

export default async function handler(req, res) {
  try {
    // входной ключ
    const keyParam = normalize(req.query?.key);

    // ключи из ENV
    const raw = process.env.VALID_KEYS || "";
    const VALID_KEYS = raw
      .split(",")
      .map(k => normalize(k))
      .filter(Boolean);

    const isValid = VALID_KEYS.includes(keyParam);

    const body = {
      valid: isValid,
      ts: Date.now() // timestamp
    };

    // Генерируем подпись
    const sig = sign(body, process.env.SIGN_SECRET || "");

    return res.status(200).json({ ...body, sig });

  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}

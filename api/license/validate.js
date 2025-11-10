// Супер-надёжная нормализация: игнорируем регистр, дефисы и странные тире
function normalize(s) {
  return String(s || "")
    .trim()
    .toLowerCase()
    // заменить все виды тире на обычный дефис
    .replace(/[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/g, "-")
    // убрать ВСЁ, что не буква/цифра (включая дефисы)
    .replace(/[^a-z0-9]/g, "");
}

export default async function handler(req, res) {
  try {
    const keyParam = normalize(req.query?.key);

    const raw = process.env.VALID_KEYS || "";
    const VALID_KEYS = raw
      .split(",")
      .map(k => normalize(k))
      .filter(Boolean);

    const isValid = keyParam.length > 0 && VALID_KEYS.includes(keyParam);

    return res.status(200).json({
      valid: isValid,
      input: keyParam,
      keys_count: VALID_KEYS.length
    });
  } catch (e) {
    return res.status(500).json({ error: "Server error" });
  }
}

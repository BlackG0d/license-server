export default async function handler(req, res) {
  try {
    // входной ключ
    const keyParam = String(req.query?.key || "")
      .trim()
      .toLowerCase();

    // ключи из ENV
    const raw = process.env.VALID_KEYS || "";
    const VALID_KEYS = raw
      .split(",")
      .map(k => k.trim().toLowerCase())
      .filter(Boolean);

    const isValid = VALID_KEYS.includes(keyParam);

    return res.status(200).json({
      valid: isValid,
      key_received: keyParam,
      valid_keys: VALID_KEYS.length
    });

  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}

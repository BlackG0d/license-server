// /api/license/validate.js
export default async function handler(req, res) {
  try {
    const { key = "" } = req.query || {};
    const raw = process.env.VALID_KEYS || "";
    const VALID_KEYS = raw.split(",").map(s => s.trim()).filter(Boolean);

    const isValid = VALID_KEYS.includes(key);
    return res.status(200).json({ valid: isValid });
  } catch (e) {
    return res.status(500).json({ error: "Server error" });
  }
}

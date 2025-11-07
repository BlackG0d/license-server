// /api/license/activate.js
export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Method not allowed" });
    }

    const AUTH = req.headers["x-auth"] || "";
    if (AUTH !== process.env.ADMIN_TOKEN) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { key } = req.body || {};
    if (!key) return res.status(400).json({ error: "Key required" });

    // NOTE: This demo endpoint doesn't persist anything.
    // In production, save this key to DB (Vercel KV / Postgres) as activated.
    return res.status(200).json({ ok: true, key });
  } catch (e) {
    return res.status(500).json({ error: "Server error" });
  }
}

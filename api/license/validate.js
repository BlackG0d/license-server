import crypto from "crypto";

// Подписываем ответ для безопасности
function sign(payload, secret) {
  return crypto.createHmac("sha256", secret)
    .update(JSON.stringify(payload))
    .digest("hex");
}

export default async function handler(req, res) {

  // ✅ Разрешаем только POST
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Use POST request" });
  }

  // ✅ Читаем key из тела запроса
  const { key } = req.body || {};

  if (!key) {
    return res.status(400).json({
      valid: false,
      reason: "Missing key in POST body"
    });
  }

  // ✅ Здесь будет БАЗА ДАННЫХ ключей (пока мок)
  const VALID_KEYS = [
    "3ASCW-WTQ9F-BP6VD-R5U6A"
  ];

  const normalizedKey = key.trim().toUpperCase();

  const isValid = VALID_KEYS.includes(normalizedKey);

  // ✅ Формируем тело ответа
  const body = {
    valid: isValid,
    ts: Date.now()
  };

  // ✅ Подписываем ответ для защиты (ключ можно хранить в .env)
  const sig = sign(body, process.env.SIGN_SECRET || "default_secret");

  // ✅ Отправляем ответ
  res.status(200).json({ ...body, sig });
}

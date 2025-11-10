// ВРЕМЕННО! Удалить после проверки.
export default function handler(req, res) {
  const raw = process.env.VALID_KEYS || "";
  const list = raw.split(",").map(s => s);
  res.status(200).json({
    hasEnv: !!raw,
    rawLength: raw.length,
    // показываем ключи как есть, чтобы заметить лишние символы
    list,
    listCount: list.length,
  });
}

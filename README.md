# License Server (Vercel)

Простой сервер проверки лицензий на Vercel.

## Эндпоинты
- `GET /api/license/validate?key=XYZ` → `{ "valid": true|false }`
- `POST /api/license/activate` (заголовок `x-auth: <ADMIN_TOKEN>`, JSON body: `{ "key": "..." }`)

## Переменные окружения (Vercel → Project → Settings → Environment Variables)
- `VALID_KEYS` — список валидных ключей через запятую, например: `ABC123,VIP-777,TEST-KEY`
- `ADMIN_TOKEN` — секретный токен для админ-операций (любой длинный случайный текст)

## Локальный запуск (при установленном Vercel CLI)
```bash
npm i -g vercel
vercel dev
```
После чего эндпоинты будут доступны на `http://localhost:3000`.

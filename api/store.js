// api/store.js
export const VALID_KEYS = new Set([
  "3ASCW-WTQ9F-BP6VD-R5U6A" // TODO: вынести в БД
]);

export const TOKENS = new Map(); // token -> { key, deviceId, exp }

// generate-key.js
const crypto = require('crypto');
const fs = require('fs');

// Генерация 32-байтного ключа (64 hex-символа)
const key = crypto.randomBytes(32).toString('hex');

// Обновление .env файла
fs.appendFileSync('.env', `\nENC_KEY=${key}\n`);

console.log(`✅ Ключ сгенерирован и добавлен в .env:\n${key}`);
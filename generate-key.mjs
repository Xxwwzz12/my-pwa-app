// generate-key.mjs
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Получение пути к текущему файлу
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Генерация 32-байтного ключа (64 hex-символа)
const key = crypto.randomBytes(32).toString('hex');

// Путь к .env файлу
const envPath = path.resolve(__dirname, '.env');

// Обновление .env файла
fs.appendFileSync(envPath, `\nENC_KEY=${key}\n`);

console.log(`✅ Ключ сгенерирован и добавлен в .env:\n${key}`);
console.log(`🔐 Проверьте файл: ${envPath}`);
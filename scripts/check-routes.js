const fs = require('fs');
const path = require('path');

const serverFile = path.join(__dirname, '../server.js');
const content = fs.readFileSync(serverFile, 'utf-8');

const invalidPatterns = [
  /app\.\w+\(['"]https?:\/\//,
  /app\.\w+\(['"][^'"]*\{[^}]+\}[^'"]*['"]/
];

invalidPatterns.forEach((pattern, i) => {
  if (pattern.test(content)) {
    console.error(`Найдены проблемные роуты в server.js (паттерн ${i+1})`);
    process.exit(1);
  }
});

console.log('Проверка роутов успешно пройдена');
const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

// Middleware для статических файлов
app.use(express.static('public'));

// API для проверки обновлений
app.get('/api/check-update', (req, res) => {
  try {
    // Динамический импорт модуля API
    const checkUpdate = require('./api/check-update');
    checkUpdate(req, res);
  } catch (error) {
    console.error('Ошибка загрузки API модуля:', error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Fallback-роут для SPA (все остальные запросы)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
  console.log(`Доступно по адресу: http://localhost:${PORT}`);
});
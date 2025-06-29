require('dotenv').config();
const express = require('express');
const app = express();

// Обработка статических файлов
app.use(express.static('public'));

// Маршрут для обработки callback от Google
app.get('/auth/callback', (req, res) => {
  // Получаем токен из параметров запроса
  const token = req.query.access_token;
  
  if (!token) {
    console.error('Token not found in callback');
    return res.status(400).send('Token not found');
  }
  
  // Перенаправляем обратно в чат с токеном в URL
  res.redirect(`/chat.html#access_token=${token}`);
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
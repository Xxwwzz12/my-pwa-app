// api/notifications.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Middleware для проверки аутентификации
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Требуется аутентификация' });

    // Временная заглушка - позже заменим реальной логикой
    req.user = { _id: 'USER_ID_FROM_TOKEN' }; 
    next();
  } catch (error) {
    res.status(500).json({ error: 'Ошибка аутентификации' });
  }
};

// Эндпоинт для получения уведомлений
router.get('/', authenticate, async (req, res) => {
  try {
    // Заглушка данных - заменим реальной логикой
    const mockData = {
      unreadMessages: 3,
      upcomingEvents: 2,
      overdueTasks: 1,
      total: 6
    };
    
    res.status(200).json(mockData);
  } catch (error) {
    res.status(500).json({ 
      error: 'Ошибка сервера при получении уведомлений',
      details: error.message
    });
  }
});

module.exports = router;

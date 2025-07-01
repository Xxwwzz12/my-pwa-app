// api/notifications.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Middleware для проверки аутентификации
const authenticate = async (req, res, next) => {
  try {
    // Используем встроенную проверку аутентификации Passport
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: 'Требуется аутентификация' });
    }
    
    // Получаем текущего пользователя из сессии
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    req.currentUser = user;
    next();
  } catch (error) {
    console.error('Ошибка аутентификации:', error);
    res.status(500).json({ error: 'Ошибка сервера при аутентификации' });
  }
};

// Эндпоинт для получения уведомлений
router.get('/', authenticate, async (req, res) => {
  try {
    // Временные mock-данные - позже заменим реальной логикой
    const notifications = {
      unreadMessages: Math.floor(Math.random() * 10),
      upcomingEvents: Math.floor(Math.random() * 5),
      overdueTasks: Math.floor(Math.random() * 3),
      total: 0
    };
    
    notifications.total = notifications.unreadMessages + notifications.upcomingEvents + notifications.overdueTasks;
    
    res.status(200).json(notifications);
  } catch (error) {
    console.error('Ошибка получения уведомлений:', error);
    res.status(500).json({ 
      error: 'Ошибка сервера при получении уведомлений',
      details: error.message
    });
  }
});

module.exports = router;

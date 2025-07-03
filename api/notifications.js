import express from 'express';
import User from '../models/User.js';

const router = express.Router();

// Улучшенный middleware аутентификации
const authenticate = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ 
      error: 'Требуется аутентификация',
      code: 'UNAUTHORIZED'
    });
  }
  next();
};

// Получение уведомлений для пользователя
router.get('/', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Расширенные mock-данные
    const notifications = {
      unreadMessages: Math.floor(Math.random() * 10),
      upcomingEvents: Math.floor(Math.random() * 5),
      overdueTasks: Math.floor(Math.random() * 3),
      total: 0,
      items: [
        {
          id: 1,
          type: 'message',
          title: 'Новое сообщение от мамы',
          body: 'Не забудь купить продукты',
          icon: '/images/assets/icon-message.webp',
          timestamp: new Date().toISOString(),
          read: false,
          source: 'family-chat'
        },
        {
          id: 2,
          type: 'event',
          title: 'Завтра день рождения',
          body: 'День рождения у папы в 19:00',
          icon: '/images/assets/icon-calendar.webp',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          read: false,
          source: 'calendar'
        },
        {
          id: 3,
          type: 'wishlist',
          title: 'Новое желание',
          body: 'Аня добавила новое желание в список',
          icon: '/images/assets/icon-wishlist.webp',
          timestamp: new Date(Date.now() - 86400000).toISOString(),
          read: true,
          source: 'wishlist'
        }
      ]
    };
    
    notifications.total = notifications.unreadMessages + 
                          notifications.upcomingEvents + 
                          notifications.overdueTasks;

    // Добавляем информацию о пользователе
    const user = await User.findById(userId);
    if (user) {
      notifications.user = {
        name: `${user.firstName} ${user.lastName}`,
        avatar: user.avatar ? `/uploads/${user.avatar}` : null
      };
    }

    res.status(200).json(notifications);
  } catch (error) {
    console.error('Ошибка получения уведомлений:', error);
    res.status(500).json({ 
      error: 'Ошибка сервера',
      code: 'SERVER_ERROR',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Пометить уведомление как прочитанное
router.put('/:id/read', authenticate, async (req, res) => {
  try {
    const notificationId = req.params.id;
    // В реальной реализации здесь было бы обновление в базе данных
    res.json({ 
      success: true, 
      message: `Уведомление ${notificationId} помечено как прочитанное`,
      notificationId
    });
  } catch (error) {
    console.error('Ошибка обновления уведомления:', error);
    res.status(500).json({ 
      error: 'Ошибка сервера',
      code: 'UPDATE_FAILED'
    });
  }
});

// Удаление уведомления
router.delete('/:id', authenticate, async (req, res) => {
  try {
    const notificationId = req.params.id;
    // В реальной реализации здесь было бы удаление из базы данных
    res.json({ 
      success: true, 
      message: `Уведомление ${notificationId} удалено`,
      notificationId
    });
  } catch (error) {
    console.error('Ошибка удаления уведомления:', error);
    res.status(500).json({ 
      error: 'Ошибка сервера',
      code: 'DELETE_FAILED'
    });
  }
});

export default router;

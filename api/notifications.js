import express from 'express';
import User from '../models/User.js';
import PushSubscription from '../models/PushSubscription.js';
import webpush from 'web-push';

const router = express.Router();

// Middleware аутентификации
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

// Сохранение подписки на push-уведомления
router.post('/save-subscription', authenticate, async (req, res) => {
  try {
    // FIX: Правильное извлечение подписки из тела запроса
    const { subscription } = req.body;
    const userId = req.user.id;
    
    // Если subscription === null, удаляем подписку
    if (subscription === null) {
      await PushSubscription.deleteMany({ userId });
      return res.status(200).json({ success: true });
    }
    
    if (!subscription || !subscription.endpoint || !subscription.keys) {
      return res.status(400).json({ 
        error: 'Неверный формат подписки',
        code: 'INVALID_SUBSCRIPTION' 
      });
    }
    
    // Поиск существующей подписки
    let existingSubscription = await PushSubscription.findOne({ 
      userId,
      endpoint: subscription.endpoint
    });
    
    if (existingSubscription) {
      // Обновляем существующую подписку
      existingSubscription.keys = subscription.keys;
      existingSubscription.expirationTime = subscription.expirationTime || null;
      await existingSubscription.save();
    } else {
      // Создаем новую подписку
      existingSubscription = new PushSubscription({
        userId,
        endpoint: subscription.endpoint,
        keys: subscription.keys,
        expirationTime: subscription.expirationTime || null
      });
      await existingSubscription.save();
    }

    res.status(201).json({ success: true });
  } catch (error) {
    console.error('Ошибка сохранения подписки:', error);
    res.status(500).json({ 
      error: 'Ошибка сервера',
      code: 'SUBSCRIPTION_SAVE_FAILED',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Отправка тестового push-уведомления
router.post('/send-push', authenticate, async (req, res) => {
  try {
    // FIX: Правильное извлечение данных
    const { subscription, title, body } = req.body;
    const userId = req.user.id;
    
    if (!subscription || !subscription.endpoint) {
      return res.status(400).json({ 
        error: 'Неверный формат подписки',
        code: 'INVALID_SUBSCRIPTION' 
      });
    }
    
    // Формирование объекта подписки для webpush
    const pushSubscription = {
      endpoint: subscription.endpoint,
      keys: {
        p256dh: subscription.keys.p256dh,
        auth: subscription.keys.auth
      }
    };
    
    // Формирование payload
    const payload = JSON.stringify({ 
      title: title || "Тестовое уведомление",
      body: body || "Это тестовое сообщение от FamilySpace",
      url: "/family.html",
      icon: "/images/assets/icon-message.webp"
    });

    // Отправка уведомления
    await webpush.sendNotification(pushSubscription, payload);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Ошибка отправки push:', error);
    
    // Обработка специфических ошибок web-push
    if (error.statusCode === 410) {
      // Устаревшая подписка - удаляем
      await PushSubscription.deleteOne({ 
        userId: req.user.id,
        endpoint: subscription.endpoint
      });
      return res.status(410).json({ 
        error: 'Подписка устарела и удалена',
        code: 'SUBSCRIPTION_EXPIRED' 
      });
    }
    
    res.status(500).json({ 
      error: 'Ошибка сервера',
      code: 'PUSH_SEND_FAILED',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Пометить уведомление как прочитанное
router.put('/:id/read', authenticate, async (req, res) => {
  try {
    const notificationId = req.params.id;
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

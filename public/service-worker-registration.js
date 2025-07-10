// Улучшенная регистрация Service Worker с поддержкой push-уведомлений
const SW_VERSION = 'v5.3.0';
const DEBUG_MODE = true;

// Функция логирования
function log(message, type = 'info') {
  if (!DEBUG_MODE) return;
  
  const styles = {
    info: 'color: #3498db;',
    success: 'color: #2ecc71;',
    warning: 'color: #f39c12;',
    error: 'color: #e74c3c;'
  };
  
  console.log(`%c[SW Register ${SW_VERSION}] ${message}`, styles[type]);
}

// Регистрация Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', async () => {
    try {
      log('Начало регистрации Service Worker', 'info');
      const registration = await navigator.serviceWorker.register('/sw.js');
      
      log(`ServiceWorker зарегистрирован с областью видимости: ${registration.scope}`, 'success');
      
      // Проверка обновлений
      registration.addEventListener('updatefound', () => {
        const newWorker = registration.installing;
        log(`Обнаружено обновление Service Worker (${newWorker.state})`, 'info');
        
        newWorker.addEventListener('statechange', () => {
          log(`Состояние нового Service Worker: ${newWorker.state}`, 'info');
          
          if (newWorker.state === 'installed') {
            if (navigator.serviceWorker.controller) {
              log('Новая версия установлена и ожидает активации', 'success');
              
              // Отправка сообщения о новой версии
              if (newWorker.postMessage) {
                newWorker.postMessage({
                  type: 'NEW_VERSION_READY',
                  version: SW_VERSION
                });
              }
              
              notifyUpdateAvailable();
            } else {
              log('Service Worker установлен впервые', 'success');
            }
          }
        });
      });
      
      // Обработка сообщений от Service Worker
      navigator.serviceWorker.addEventListener('message', event => {
        if (!event.data) return;
        
        switch (event.data.type) {
          case 'SW_LOG':
            log(`[SW] ${event.data.message}`, 'info');
            break;
            
          case 'NEW_VERSION_AVAILABLE':
            log(`Получено сообщение о новой версии: ${event.data.version}`, 'info');
            notifyUpdateAvailable();
            break;
            
          case 'PUSH_SUBSCRIPTION_EXPIRED':
            log('Подписка на push-уведомления устарела', 'warning');
            handleExpiredSubscription();
            break;
        }
      });
      
      // Проверка новой версии при запуске
      if (registration.waiting) {
        notifyUpdateAvailable();
      }
      
      // Периодическая проверка обновлений
      setInterval(() => {
        log('Фоновая проверка обновлений...', 'info');
        registration.update().catch(err => {
          log(`Ошибка при проверке обновлений: ${err}`, 'error');
        });
      }, 60 * 60 * 1000); // Каждый час
      
      // Инициализация push-менеджера
      initPushManager(registration);
      
    } catch (error) {
      log(`Ошибка регистрации Service Worker: ${error}`, 'error');
    }
  });
}

// Показ уведомления об обновлении
function notifyUpdateAvailable() {
  log('Показ уведомления об обновлении', 'info');
  
  if (Notification.permission === 'granted') {
    const notification = new Notification('Доступно обновление', {
      body: 'Нажмите, чтобы обновить приложение',
      icon: '/images/assets/logo.webp',
      vibrate: [200, 100, 200],
      tag: 'update-notification'
    });
    
    notification.onclick = () => {
      window.location.reload();
      notification.close();
    };
    
    // Автоматическое закрытие через 15 секунд
    setTimeout(() => notification.close(), 15000);
    
  } else if (confirm('Доступна новая версия приложения. Обновить сейчас?')) {
    window.location.reload();
  }
}

// Инициализация PushManager
function initPushManager(registration) {
  if (!('PushManager' in window)) {
    log('Браузер не поддерживает Push API', 'warning');
    return;
  }
  
  // Проверка состояния подписки
  registration.pushManager.getSubscription()
    .then(subscription => {
      if (subscription) {
        log('Найдена существующая подписка на push-уведомления', 'success');
        // Проверка валидности подписки
        checkSubscriptionValidity(subscription);
      } else {
        log('Активная подписка не найдена', 'info');
      }
    })
    .catch(err => {
      log(`Ошибка проверки подписки: ${err}`, 'error');
    });
}

// Проверка валидности подписки
function checkSubscriptionValidity(subscription) {
  // Здесь могла бы быть проверка с сервером
  log(`Проверка подписки: ${subscription.endpoint}`, 'info');
  
  // Эвристика: если подписка старше 90 дней, считаем устаревшей
  const subscriptionDate = new Date(subscription.expirationTime || Date.now());
  const ninetyDaysAgo = new Date();
  ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
  
  if (subscriptionDate < ninetyDaysAgo) {
    log('Подписка устарела (старше 90 дней)', 'warning');
    handleExpiredSubscription();
  }
}

// Обработка устаревшей подписки
function handleExpiredSubscription() {
  // Отправим сообщение на страницу
  const event = new CustomEvent('pushSubscriptionExpired');
  window.dispatchEvent(event);
  
  // Покажем уведомление если есть разрешение
  if (Notification.permission === 'granted') {
    const notification = new Notification('Обновите подписку', {
      body: 'Ваша подписка на уведомления устарела',
      icon: '/images/assets/logo.webp',
      tag: 'subscription-expired'
    });
    
    notification.onclick = () => {
      window.focus();
      notification.close();
    };
  }
}

// Проверка обновлений по команде пользователя
window.checkForUpdates = async () => {
  if ('serviceWorker' in navigator) {
    try {
      const registration = await navigator.serviceWorker.ready;
      log('Ручная проверка обновлений...', 'info');
      
      await registration.update();
      log('Приложение успешно обновлено!', 'success');
      
      // Показать уведомление
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('Приложение обновлено', {
          body: 'Новая версия успешно загружена',
          icon: '/images/assets/logo.webp'
        });
      }
      
    } catch (error) {
      log(`Ошибка при обновлении: ${error}`, 'error');
    }
  } else {
    log('Браузер не поддерживает Service Workers', 'warning');
  }
};

// Отправка сообщения Service Worker
window.sendMessageToSW = (message) => {
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    navigator.serviceWorker.controller.postMessage(message);
  }
};

// Запрос VAPID-ключа у Service Worker
window.getVAPIDKey = () => {
  return new Promise((resolve, reject) => {
    if (!('serviceWorker' in navigator)) {
      reject('Service Worker не поддерживается');
      return;
    }
    
    const messageChannel = new MessageChannel();
    messageChannel.port1.onmessage = event => {
      if (event.data && event.data.type === 'VAPID_KEY') {
        resolve(event.data.key);
      } else {
        reject('Не удалось получить ключ');
      }
    };
    
    navigator.serviceWorker.controller.postMessage(
      { type: 'GET_VAPID_KEY' },
      [messageChannel.port2]
    );
    
    // Таймаут на случай отсутствия ответа
    setTimeout(() => {
      reject('Таймаут получения VAPID-ключа');
    }, 3000);
  });
};

// Очистка кэша
window.clearSWCache = () => {
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    navigator.serviceWorker.controller.postMessage({ type: 'CLEAR_CACHE' });
    log('Отправлена команда очистки кэша', 'info');
    return true;
  }
  return false;
};

// Событие для обработки устаревшей подписки
window.addEventListener('pushSubscriptionExpired', () => {
  log('Получено событие об устаревшей подписке', 'warning');
  
  // В реальном приложении здесь можно показать UI-уведомление
  if (confirm('Ваша подписка на уведомления устарела. Обновить подписку?')) {
    // Перезапустить процесс подписки
    if (window.resubscribeToPush) {
      window.resubscribeToPush();
    }
  }
});

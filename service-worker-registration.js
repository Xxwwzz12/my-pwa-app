// Регистрация Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', async () => {
    try {
      const registration = await navigator.serviceWorker.register('/sw.js');
      
      console.log('ServiceWorker зарегистрирован с областью видимости: ', registration.scope);
      
      // Проверка обновлений
      registration.addEventListener('updatefound', () => {
        const newWorker = registration.installing;
        console.log('Обнаружено обновление Service Worker');
        
        newWorker.addEventListener('statechange', () => {
          if (newWorker.state === 'installed') {
            if (navigator.serviceWorker.controller) {
              console.log('Доступна новая версия приложения');
              
              // Отправляем сообщение о новой версии
              registration.active.postMessage({
                type: 'NEW_VERSION_READY',
                version: 'v3.0'
              });
              
              // Показываем уведомление пользователю
              showUpdateNotification();
            }
          }
        });
      });
      
      // Проверка новой версии при запуске
      if (registration.waiting) {
        showUpdateNotification();
      }
      
      // Периодическая проверка обновлений
      setInterval(() => {
        registration.update().catch(err => {
          console.log('Ошибка при проверке обновлений: ', err);
        });
      }, 60 * 60 * 1000); // Каждый час
      
    } catch (error) {
      console.error('Ошибка регистрации Service Worker: ', error);
    }
  });
}

// Показ уведомления об обновлении
function showUpdateNotification() {
  if (Notification.permission === 'granted') {
    new Notification('Доступно обновление', {
      body: 'Нажмите, чтобы обновить приложение',
      icon: '/icon-192.png',
      vibrate: [200, 100, 200]
    }).onclick = () => {
      window.location.reload();
    };
  } else if (confirm('Доступна новая версия приложения. Обновить сейчас?')) {
    window.location.reload();
  }
}

// Проверка обновлений по команде пользователя
window.checkForUpdates = async () => {
  if ('serviceWorker' in navigator) {
    const registration = await navigator.serviceWorker.ready;
    
    try {
      await registration.update();
      alert('Приложение успешно обновлено!');
    } catch (error) {
      console.error('Ошибка при обновлении: ', error);
      alert('Не удалось проверить обновления. Пожалуйста, проверьте подключение к интернету.');
    }
  } else {
    alert('Ваш браузер не поддерживает автоматические обновления');
  }
};

// Отправка сообщения Service Worker
window.sendMessageToSW = (message) => {
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    navigator.serviceWorker.controller.postMessage(message);
  }
};

// Обработка входящих сообщений от Service Worker
navigator.serviceWorker.addEventListener('message', event => {
  switch (event.data.type) {
    case 'NEW_VERSION_AVAILABLE':
      console.log('Доступна новая версия: ', event.data.version);
      showUpdateNotification();
      break;
      
    case 'SW_LOG':
      console.log('[SW Log]', event.data.message);
      break;
      
    default:
      console.log('Получено сообщение от SW:', event.data);
  }
});
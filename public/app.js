// Централизованный обработчик ошибок
window.addEventListener('error', (event) => {
  console.error('Глобальная ошибка:', event.error);
  
  // Отправка ошибки на сервер (если есть соединение)
  if (navigator.onLine) {
    const errorData = {
      message: event.error.message,
      stack: event.error.stack,
      filename: event.filename,
      lineno: event.lineno,
      colno: event.colno,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent
    };
    
    fetch('/api/error-log', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(errorData)
    }).catch(() => {/* Не обрабатываем ошибки отправки ошибок */});
  }
  
  // Показ пользователю понятного сообщения
  if (window.showErrorNotification) {
    showErrorNotification('Произошла непредвиденная ошибка. Пожалуйста, попробуйте позже.');
  } else {
    alert('Произошла ошибка в приложении. Мы уже работаем над её устранением.');
  }
});

// Функция для показа уведомлений об ошибках
window.showErrorNotification = (message) => {
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification('Ошибка в приложении', {
      body: message,
      icon: '/icon-192.png'
    });
  } else {
    const errorElement = document.createElement('div');
    errorElement.style = `
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: #ff6b6b;
      color: white;
      padding: 15px 25px;
      border-radius: 10px;
      z-index: 10000;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      animation: fadeIn 0.3s;
    `;
    
    errorElement.textContent = message;
    document.body.appendChild(errorElement);
    
    setTimeout(() => {
      errorElement.style.animation = 'fadeOut 0.3s';
      setTimeout(() => document.body.removeChild(errorElement), 300);
    }, 5000);
  }
};

// Инициализация PWA функций
window.initializePWA = () => {
  // Проверка установки приложения
  if (window.matchMedia('(display-mode: standalone)').matches) {
    console.log('Приложение запущено в standalone режиме');
    document.documentElement.classList.add('pwa-mode');
  }
  
  // Обработчик для кнопки "Установить"
  if ('beforeinstallprompt' in window) {
    let deferredPrompt;
    
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e;
      
      const installButton = document.getElementById('install-button');
      if (installButton) {
        installButton.style.display = 'block';
        installButton.addEventListener('click', () => {
          deferredPrompt.prompt();
          deferredPrompt.userChoice.then(() => {
            deferredPrompt = null;
          });
        });
      }
    });
  }
};

// Инициализация при загрузке
window.addEventListener('DOMContentLoaded', () => {
  initializePWA();
  
  // Проверка поддержки функций
  if (!('serviceWorker' in navigator)) {
    showErrorNotification('Ваш браузер не поддерживает все функции приложения');
  }
  
  if (!('indexedDB' in window)) {
    showErrorNotification('Ваш браузер не поддерживает оффлайн-хранилище');
  }
});
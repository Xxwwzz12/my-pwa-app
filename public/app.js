import { initCsrf, fetchWithCsrf } from './utils/csrf.js';

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
    
    // Используем fetchWithCsrf вместо fetch
    fetchWithCsrf('/api/error-log', {
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
    alert('Произошла ошибка в приложении. Мы уже работают над её устранением.');
  }
});

// Функция для показа уведомлений об ошибках
window.showErrorNotification = (message) => {
  // Безопасное использование: textContent вместо innerHTML (#271)
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
    
    // Используем textContent для безопасности (#271)
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

// Инициализация IndexedDB (#174) - нативный API
window.initializeIndexedDB = () => {
  if (!('indexedDB' in window)) return;
  
  const request = indexedDB.open('app-db', 1);
  
  request.onupgradeneeded = (event) => {
    const db = event.target.result;
    if (!db.objectStoreNames.contains('cache')) {
      db.createObjectStore('cache');
    }
  };
  
  request.onsuccess = (event) => {
    window.idb = event.target.result;
  };
  
  request.onerror = (event) => {
    console.error('Ошибка открытия IndexedDB', event.target.error);
  };
};

// ================== РЕАЛИЗАЦИЯ РОУТЕРА ================== //
class Router {
  constructor() {
    this.routes = {
      '/family/:id': this.handleFamilyRoute,
      '/chat/:id': this.handleChatRoute,
      '/': this.handleHomeRoute
    };
    this.currentController = null;
    this.cache = new Map();
  }

  // Обработчики маршрутов
  handleFamilyRoute(params) {
    return new FamilyController(params.id);
  }

  handleChatRoute(params) {
    return new ChatController(params.id);
  }

  async handleHomeRoute() {
    // Динамическая загрузка модуля (#233)
    const module = await import('./controllers/home-controller.js');
    return new module.default();
  }

  // Сопоставление пути с маршрутом
  matchRoute(path) {
    const pathSegments = path.split('/').filter(Boolean);
    
    for (const [routePattern, handler] of Object.entries(this.routes)) {
      const patternSegments = routePattern.split('/').filter(Boolean);
      
      if (pathSegments.length !== patternSegments.length) continue;
      
      const params = {};
      let match = true;
      
      for (let i = 0; i < patternSegments.length; i++) {
        if (patternSegments[i].startsWith(':')) {
          const paramName = patternSegments[i].slice(1);
          params[paramName] = pathSegments[i];
        } else if (patternSegments[i] !== pathSegments[i]) {
          match = false;
          break;
        }
      }
      
      if (match) return [routePattern, params];
    }
    
    return [null, null];
  }

  // Навигация между маршрутами
  async navigate(path) {
    try {
      // Очистка предыдущего контроллера
      if (this.currentController?.destroy) {
        await this.currentController.destroy();
        this.currentController = null;
      }
      
      // Проверка доступности сети
      if (!navigator.onLine) {
        const cached = await this.getCachedContent(path);
        if (cached) {
          document.body.innerHTML = cached;
          return;
        }
      }
      
      // Поиск совпадения маршрута
      const [matchedRoute, params] = this.matchRoute(path);
      
      if (matchedRoute) {
        this.currentController = this.routes[matchedRoute](params);
        await this.currentController.init();
        
        // Кеширование контента (#224)
        this.cacheContent(path, document.body.innerHTML);
        
        // Обновление истории
        history.pushState({ path }, '', path);
      } else {
        this.show404();
      }
    } catch (error) {
      console.error('Ошибка навигации:', error);
      this.showError(`Ошибка загрузки: ${error.message}`);
    }
  }

  // Кеширование контента (#224)
  cacheContent(path, content) {
    this.cache.set(path, content);
    
    // Интеграция с IndexedDB
    if (window.idb) {
      const transaction = window.idb.transaction('cache', 'readwrite');
      transaction.objectStore('cache').put(content, `route-${path}`);
    }
  }

  // Получение кешированного контента
  async getCachedContent(path) {
    // Проверка in-memory кеша
    if (this.cache.has(path)) return this.cache.get(path);
    
    // Проверка IndexedDB
    if (window.idb) {
      try {
        const transaction = window.idb.transaction('cache', 'readonly');
        const store = transaction.objectStore('cache');
        return await store.get(`route-${path}`);
      } catch (e) {
        console.warn('Ошибка чтения кеша:', e);
      }
    }
    
    return null;
  }

  // Обработка 404 ошибки
  show404() {
    showErrorNotification('Страница не найдена');
    history.replaceState(null, null, '/404');
  }

  // Показать ошибку
  showError(message) {
    showErrorNotification(message);
  }

  // Инициализация обработчиков событий
  initEventListeners() {
    // Обработка кликов по ссылкам
    document.addEventListener('click', e => {
      const link = e.target.closest('[data-link]');
      if (link) {
        e.preventDefault();
        this.navigate(link.getAttribute('href'));
      }
    });
    
    // Обработка истории браузера
    window.addEventListener('popstate', e => {
      if (e.state?.path) {
        this.navigate(e.state.path);
      } else {
        this.navigate('/');
      }
    });
  }

  // Регистрация Service Worker
  registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/sw.js')
        .then(reg => {
          console.log('Service Worker зарегистрирован:', reg);
          
          // Обработка обновлений SW
          reg.addEventListener('updatefound', () => {
            const newWorker = reg.installing;
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                showErrorNotification('Доступно обновление. Перезагрузите страницу.');
              }
            });
          });
        })
        .catch(err => {
          console.error('Ошибка регистрации SW:', err);
        });
    }
  }
}

// Базовые реализации контроллеров (должны быть в отдельных файлах)
class FamilyController {
  constructor(familyId) {
    this.familyId = familyId;
  }
  
  async init() {
    console.log(`Инициализация семейного контроллера для ID: ${this.familyId}`);
    // Реальная реализация должна быть в ./controllers/family-controller.js
    document.body.innerHTML = `<h1>Семейный профиль ${this.familyId}</h1>`;
    
    // Пример использования fetchWithCsrf в контроллере
    try {
      const response = await fetchWithCsrf(`/api/family/${this.familyId}`, {
        method: 'PUT',
        body: JSON.stringify({ lastVisited: Date.now() })
      });
      // ... обработка ответа ...
    } catch (error) {
      console.error('Ошибка обновления данных семьи', error);
    }
  }
  
  async destroy() {
    console.log(`Очистка ресурсов семейного контроллера ${this.familyId}`);
  }
}

class ChatController {
  constructor(chatId) {
    this.chatId = chatId;
  }
  
  async init() {
    console.log(`Инициализация чат-контроллера для ID: ${this.chatId}`);
    // Реальная реализация должна быть в ./controllers/chat-controller.js
    document.body.innerHTML = `<h1>Чат ${this.chatId}</h1>`;
    
    // Пример использования fetchWithCsrf в контроллере
    try {
      const response = await fetchWithCsrf(`/api/chat/${this.chatId}/messages`, {
        method: 'POST',
        body: JSON.stringify({ text: 'Привет!' })
      });
      // ... обработка ответа ...
    } catch (error) {
      console.error('Ошибка отправки сообщения', error);
    }
  }
  
  async destroy() {
    console.log(`Очистка ресурсов чат-контроллера ${this.chatId}`);
  }
}

// ================== ИНИЦИАЛИЗАЦИЯ ПРИЛОЖЕНИЯ ================== //
document.addEventListener('DOMContentLoaded', async () => {
  // Инициализация CSRF (#295)
  try {
    await initCsrf();
    console.log('CSRF защита инициализирована');
  } catch (error) {
    console.error('Ошибка инициализации CSRF:', error);
    showErrorNotification('Ошибка безопасности. Пожалуйста, перезагрузите страницу.');
  }
  
  // Глобальная инициализация
  initializePWA();
  initializeIndexedDB();
  
  // Инициализация роутера
  const router = new Router();
  router.initEventListeners();
  router.registerServiceWorker();
  
  // Первоначальная навигация
  await router.navigate(window.location.pathname);
});
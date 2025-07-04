// ===== Service Worker для FamilySpace PWA (v5.3.1) =====
const CACHE_VERSION = 'v5.3.1'; // Фикс версии
const CACHE_NAME = `familyspace-cache-${CACHE_VERSION}`;
const API_CACHE_NAME = 'familyspace-api-cache-v2';
const OFFLINE_URL = '/offline.html';
const VAPID_PUBLIC_KEY = 'BHlRR33D_L19ZAfcmTqJz9boQacOqRAVBwx4beTj7UgKWBX9ZkYbW0oOfZAtbdCT9jaCJWQ3ng5VaaUrWU8KJLo'; // Прямое значение ключа

// Ресурсы для предварительного кэширования
const PRECACHE_RESOURCES = [
  '/',
  '/index.html',
  '/family.html',
  '/profile.html',
  '/registration.html',
  '/family-chat.html',
  '/chat.html',
  '/calendar.html',
  '/tasks.html',
  '/wishlist.html',
  '/test-notifications.html',
  '/offline.html',
  '/favicon.ico',
  '/style.css',
  '/manifest.json',
  '/images/assets/logo.webp',
  '/images/assets/default.webp',
  '/images/assets/vista-bg.webp',
  '/images/assets/badge.webp',
  '/images/assets/icon-message.webp',
  '/images/assets/icon-calendar.webp',
  '/images/assets/icon-wishlist.webp',
  '/js/api.js',
  '/js/auth.js',
  '/js/index.js',
  '/service-worker-registration.js'
];

// Критические API эндпоинты
const CRITICAL_API_ENDPOINTS = [
  '/api/notifications',
  '/api/recent-activity',
  '/api/check-update',
  '/api/user-info',
  '/api/vapid-public-key'
];

// Эндпоинты без кэширования
const NO_CACHE_ENDPOINTS = [
  '/api/save-subscription',
  '/api/send-push',
  '/api/auth'
];

// Улучшенное логирование
function log(message) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] SW v${CACHE_VERSION}: ${message}`;
  
  console.log(logEntry);
  
  // Отправка логов клиентам
  self.clients.matchAll().then(clients => {
    clients.forEach(client => {
      client.postMessage({
        type: 'SW_LOG',
        message: logEntry
      });
    });
  });
}

// Установка Service Worker
self.addEventListener('install', event => {
  log(`Установка новой версии: ${CACHE_NAME}`);
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        log('Кэширование основных ресурсов');
        return cache.addAll(PRECACHE_RESOURCES);
      })
      .then(() => {
        log('Все ресурсы успешно кэшированы');
        return self.skipWaiting();
      })
      .catch(error => {
        log(`Критическая ошибка при установке: ${error.message}`);
        throw error;
      })
  );
});

// Активация Service Worker
self.addEventListener('activate', event => {
  log(`Активация версии ${CACHE_VERSION}`);
  
  const cacheWhitelist = [CACHE_NAME, API_CACHE_NAME];
  
  event.waitUntil(
    caches.keys()
      .then(cacheNames => Promise.all(
        cacheNames.map(cacheName => {
          if (!cacheWhitelist.includes(cacheName)) {
            log(`Удаление старого кэша: ${cacheName}`);
            return caches.delete(cacheName);
          }
        })
      ))
      .then(() => {
        log('Активация завершена. Принимаем контроль над клиентами');
        return self.clients.claim();
      })
      .then(() => {
        // Уведомление клиентов о новой версии
        self.clients.matchAll({ type: 'window' }).then(clients => {
          clients.forEach(client => {
            client.postMessage({
              type: 'NEW_VERSION_AVAILABLE',
              version: CACHE_VERSION
            });
          });
        });
      })
  );
});

// Обработчик запросов с улучшенной обработкой ошибок
self.addEventListener('fetch', event => {
  const requestUrl = new URL(event.request.url);
  const pathname = requestUrl.pathname;
  
  // Пропускаем не-GET запросы и исключенные эндпоинты
  if (event.request.method !== 'GET' || 
      NO_CACHE_ENDPOINTS.some(endpoint => pathname.startsWith(endpoint))) {
    return fetch(event.request);
  }
  
  const isApiRequest = pathname.startsWith('/api/');
  const isStaticResource = /\.(css|js|png|jpg|jpeg|gif|svg|ico|json|webp)$/.test(pathname);
  
  log(`Запрос: ${pathname} [${isApiRequest ? 'API' : isStaticResource ? 'Static' : 'Navigation'}]`);
  
  // Стратегия для критических API: Network First
  if (isApiRequest && CRITICAL_API_ENDPOINTS.some(endpoint => pathname.startsWith(endpoint))) {
    event.respondWith(handleCriticalApiRequest(event));
    return;
  }
  
  // Стратегия для статики: Cache First
  if (isStaticResource) {
    event.respondWith(handleStaticRequest(event));
    return;
  }
  
  // Стратегия для навигации: Network First
  event.respondWith(handleNavigationRequest(event));
});

// Обработка критических API запросов
async function handleCriticalApiRequest(event) {
  try {
    const response = await fetchWithTimeout(event.request, 3000);
    
    // Кэшируем успешные GET-ответы
    if (event.request.method === 'GET' && response.ok) {
      const clone = response.clone();
      caches.open(API_CACHE_NAME)
        .then(cache => cache.put(event.request, clone))
        .catch(err => log(`Ошибка кэширования API: ${err}`));
    }
    
    return response;
  } catch (error) {
    log(`Сбой сети для API: ${error.message}`);
    
    // Пытаемся вернуть данные из кэша
    const cachedResponse = await caches.match(event.request);
    if (cachedResponse) {
      log(`Используем кэшированный ответ для: ${event.request.url}`);
      return cachedResponse;
    }
    
    // Fallback для эндпоинта уведомлений
    if (event.request.url.includes('/api/notifications')) {
      return new Response(JSON.stringify({
        unreadMessages: 0,
        upcomingEvents: 0,
        overdueTasks: 0,
        total: 0
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Общий fallback для API
    return new Response(JSON.stringify({ 
      error: "Service unavailable",
      message: "Попробуйте позже" 
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Обработка статических запросов
async function handleStaticRequest(event) {
  try {
    // Сначала пытаемся получить из кэша
    const cachedResponse = await caches.match(event.request);
    if (cachedResponse) return cachedResponse;
    
    // Если нет в кэше - сетевой запрос
    const response = await fetch(event.request);
    
    // Кэшируем успешные ответы
    if (response.ok) {
      const clone = response.clone();
      caches.open(CACHE_NAME)
        .then(cache => cache.put(event.request, clone))
        .catch(err => log(`Ошибка кэширования: ${err}`));
    }
    
    return response;
  } catch (error) {
    log(`Ошибка загрузки ресурса: ${event.request.url} - ${error.message}`);
    
    // Fallback для изображений
    if (/\.(png|jpg|jpeg|gif|svg|webp)$/.test(event.request.url)) {
      const fallback = await caches.match('/images/assets/default.webp');
      if (fallback) return fallback;
    }
    
    // Fallback для favicon
    if (event.request.url.includes('favicon.ico')) {
      const fallback = await caches.match('/favicon.ico');
      if (fallback) return fallback;
    }
    
    return Response.error();
  }
}

// Обработка навигационных запросов
async function handleNavigationRequest(event) {
  try {
    const response = await fetch(event.request);
    
    // Обновляем кэш для успешных ответов
    if (response.ok && event.request.method === 'GET') {
      const clone = response.clone();
      caches.open(CACHE_NAME)
        .then(cache => cache.put(event.request, clone));
    }
    
    return response;
  } catch (error) {
    log(`Ошибка навигации: ${error.message}`);
    
    // Возвращаем offline-страницу
    const offlinePage = await caches.match(OFFLINE_URL);
    if (offlinePage) return offlinePage;
    
    // Fallback для корневой страницы
    return caches.match('/index.html');
  }
}

// Обработчик push-уведомлений
self.addEventListener('push', event => {
  log('Получено push-событие');
  
  try {
    const payload = event.data ? event.data.json() : null;
    const title = payload?.title || 'FamilySpace';
    const body = payload?.body || 'Новое уведомление';
    const url = payload?.url || '/';
    const icon = payload?.icon || '/images/assets/logo.webp';
    const badge = payload?.badge || '/images/assets/badge.webp';
    
    const options = {
      body,
      icon,
      badge,
      data: { url },
      vibrate: [200, 100, 200],
      timestamp: Date.now()
    };
    
    event.waitUntil(
      self.registration.showNotification(title, options)
    );
    
    log(`Уведомление показано: "${title}"`);
  } catch (error) {
    log(`Ошибка обработки push-события: ${error.message}`);
    
    // Fallback для некорректных данных
    event.waitUntil(
      self.registration.showNotification('FamilySpace', {
        body: 'Новое уведомление',
        icon: '/images/assets/logo.webp',
        badge: '/images/assets/badge.webp',
        data: { url: '/' }
      })
    );
  }
});

// Обработчик кликов по уведомлениям
self.addEventListener('notificationclick', event => {
  event.notification.close();
  
  const url = event.notification.data.url || '/';
  log(`Клик по уведомлению. Переход на: ${url}`);
  
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(windowClients => {
      // Проверяем, есть ли открытая вкладка с нужным URL
      for (const client of windowClients) {
        if (client.url === url && 'focus' in client) {
          return client.focus();
        }
      }
      
      // Если нет открытой вкладки - открываем новую
      if (clients.openWindow) {
        return clients.openWindow(url);
      }
      
      return null;
    })
  );
});

// Обработчик сообщений
self.addEventListener('message', event => {
  if (!event.data) return;
  
  switch (event.data.type) {
    case 'SKIP_WAITING':
      log('Получена команда SKIP_WAITING');
      self.skipWaiting();
      event.source.postMessage({ type: 'RELOAD_REQUIRED' });
      break;
      
    case 'GET_VAPID_KEY':
      log('Запрос VAPID-ключа');
      event.source.postMessage({ 
        type: 'VAPID_KEY',
        key: VAPID_PUBLIC_KEY // Использование прямой константы
      });
      break;
      
    case 'CLEAR_CACHE':
      log('Получена команда CLEAR_CACHE');
      caches.keys().then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => caches.delete(cacheName))
        ).then(() => {
          event.source.postMessage({ type: 'CACHE_CLEARED' });
        });
      });
      break;
      
    case 'GET_STATE':
      event.source.postMessage({
        type: 'SW_STATE',
        version: CACHE_VERSION,
        cacheNames: Array.from(caches.keys()),
        isControlled: !!self.clients.matchAll().length
      });
      break;
  }
});

// Вспомогательная функция: fetch с таймаутом
function fetchWithTimeout(request, timeout) {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
      reject(new Error(`Timeout after ${timeout}ms`));
    }, timeout);
    
    fetch(request, { signal: controller.signal })
      .then(response => {
        clearTimeout(timeoutId);
        resolve(response);
      })
      .catch(error => {
        clearTimeout(timeoutId);
        reject(error);
      });
  });
}

// Инициализация
log(`Service Worker v${CACHE_VERSION} запущен`);

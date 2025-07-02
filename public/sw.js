// Версия кэша
const CACHE_VERSION = 'v5.0';
const CACHE_NAME = `familyspace-cache-${CACHE_VERSION}`;
const API_CACHE_NAME = 'familyspace-api-cache-v2';
const OFFLINE_URL = '/offline.html';
const LOGS_DB_NAME = 'FamilySpace_Logs_DB';
const LOGS_STORE_NAME = 'logs';
const MAX_LOGS = 100;

// VAPID Public Key
const VAPID_PUBLIC_KEY = 'BHlRR33D_L19ZAfcmTqJz9boQacOqRAVBwx4beTj7UgKWBX9ZkYbW0oOfZAtbdCT9jaCJWQ3ng5VaaUrWU8KJLo';

// Список ресурсов для предварительного кэширования
const PRECACHE_RESOURCES = [
  '/',
  '/index.html',
  '/family.html',
  '/profile.html',
  '/registration.html',
  '/family-chat.html',
  '/calendar.html',
  '/tasks.html',
  '/wishlist.html',
  '/offline.html',
  '/styles.css',
  '/manifest.json',
  '/images/logo.webp',
  '/images/default.webp',
  '/images/vista-bg.webp',
  '/images/badge.webp',
  '/js/api.js',
  '/js/auth.js',
  '/js/index.js'
];

// Критические API эндпоинты для кэширования
const CRITICAL_API_ENDPOINTS = [
  '/api/notifications',
  '/api/recent-activity',
  '/api/check-update',
  '/api/user-info'
];

// Улучшенная система логов с IndexedDB
function log(message) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] FamilySpace SW: ${message}`;
  
  // Сохраняем лог в IndexedDB
  saveLogToDB(logEntry);
  
  console.log(logEntry);
  
  // Отправляем лог всем клиентам
  self.clients.matchAll().then(clients => {
    clients.forEach(client => {
      client.postMessage({
        type: 'SW_LOG',
        message: logEntry
      });
    });
  });
}

// Инициализация IndexedDB
function initDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(LOGS_DB_NAME, 1);
    
    request.onerror = (event) => {
      console.error('IndexedDB error:', event.target.error);
      reject(event.target.error);
    };
    
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(LOGS_STORE_NAME)) {
        db.createObjectStore(LOGS_STORE_NAME, { autoIncrement: true });
      }
      // Создаем хранилище для подписок
      if (!db.objectStoreNames.contains('push_subscriptions')) {
        db.createObjectStore('push_subscriptions');
      }
    };
    
    request.onsuccess = (event) => {
      resolve(event.target.result);
    };
  });
}

// Сохранение лога в IndexedDB
function saveLogToDB(logEntry) {
  initDB().then(db => {
    const transaction = db.transaction(LOGS_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(LOGS_STORE_NAME);
    
    // Добавляем лог
    store.add(logEntry);
    
    // Очищаем старые логи
    store.getAll().onsuccess = (event) => {
      const allLogs = event.target.result;
      if (allLogs.length > MAX_LOGS) {
        const keysToDelete = allLogs
          .slice(0, allLogs.length - MAX_LOGS)
          .map((_, index) => index + 1);
        
        keysToDelete.forEach(key => {
          store.delete(key);
        });
      }
    };
  }).catch(error => {
    console.error('Failed to save log:', error);
  });
}

// Получение логов из IndexedDB
function getLogsFromDB() {
  return new Promise((resolve, reject) => {
    initDB().then(db => {
      const transaction = db.transaction(LOGS_STORE_NAME, 'readonly');
      const store = transaction.objectStore(LOGS_STORE_NAME);
      const request = store.getAll();
      
      request.onsuccess = (event) => {
        resolve(event.target.result || []);
      };
      
      request.onerror = (event) => {
        reject(event.target.error);
      };
    }).catch(reject);
  });
}

// Установка Service Worker
self.addEventListener('install', event => {
  log(`Установка новой версии: ${CACHE_NAME}`);
  
  // Пропускаем этап ожидания для немедленной активации
  self.skipWaiting();
  
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
        log(`Ошибка при установке: ${error.message}`);
      })
  );
});

// Активация Service Worker
self.addEventListener('activate', event => {
  log('Активация Service Worker');
  
  const cacheWhitelist = [CACHE_NAME, API_CACHE_NAME];
  
  event.waitUntil(
    caches.keys().then(cacheNames => {
      log(`Найдено кэшей: ${cacheNames.length}`);
      return Promise.all(
        cacheNames.map(cacheName => {
          if (!cacheWhitelist.includes(cacheName)) {
            log(`Удаление старого кэша: ${cacheName}`);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      // Немедленно забираем контроль над страницами
      log('Захват контроля над клиентами');
      return self.clients.claim();
    })
    .then(() => {
      // Сообщаем клиентам о новой версии
      self.clients.matchAll({ type: 'window' }).then(clients => {
        clients.forEach(client => {
          log(`Отправка NEW_VERSION_AVAILABLE клиенту: ${client.url}`);
          client.postMessage({
            type: 'NEW_VERSION_AVAILABLE',
            version: CACHE_VERSION
          });
        });
      });
    })
  );
});

// Обработка запросов
self.addEventListener('fetch', event => {
  const requestUrl = new URL(event.request.url);
  const isApiRequest = requestUrl.pathname.startsWith('/api/');
  const isStaticResource = /\.(css|js|png|jpg|jpeg|gif|svg|ico|json|webp)$/.test(requestUrl.pathname);
  
  log(`Запрос: ${requestUrl.pathname} [${isApiRequest ? 'API' : isStaticResource ? 'Static' : 'Navigation'}]`);
  
  // Стратегия для критических API запросов: Network First с кэшированием
  if (isApiRequest && CRITICAL_API_ENDPOINTS.some(endpoint => requestUrl.pathname.startsWith(endpoint))) {
    event.respondWith(
      fetch(event.request))
        .then(networkResponse => {
          // Кэшируем только GET запросы и успешные ответы
          if (event.request.method === 'GET' && networkResponse.ok) {
            const responseClone = networkResponse.clone();
            caches.open(API_CACHE_NAME)
              .then(cache => cache.put(event.request, responseClone))
              .catch(err => log(`Ошибка кэширования API: ${err}`));
          }
          return networkResponse;
        })
        .catch(() => {
          // При ошибке сети - возвращаем из кэша
          return caches.match(event.request))
            .then(cachedResponse => {
              if (cachedResponse) {
                log(`Используем кэшированный ответ для: ${requestUrl.pathname}`);
                return cachedResponse;
              }
              
              // Для API уведомлений возвращаем fallback
              if (requestUrl.pathname === '/api/notifications') {
                return new Response(JSON.stringify({
                  unreadMessages: 0,
                  upcomingEvents: 0,
                  overdueTasks: 0,
                  total: 0
                }), {
                  headers: { 'Content-Type': 'application/json' }
                });
              }
              
              return Response.error();
            });
        })
    );
    return;
  }

  // Стратегия для статических ресурсов: Cache First
  if (isStaticResource) {
    event.respondWith(
      caches.match(event.request))
        .then(cachedResponse => {
          // Возвращаем кэшированный ответ если он есть
          if (cachedResponse) {
            log(`Обслуживаем из кэша: ${requestUrl.pathname}`);
            return cachedResponse;
          }
          
          // Иначе загружаем из сети и кэшируем
          return fetch(event.request))
            .then(networkResponse => {
              // Клонируем ответ для кэширования
              const responseClone = networkResponse.clone();
              caches.open(CACHE_NAME))
                .then(cache => cache.put(event.request, responseClone))
                .catch(err => log(`Ошибка кэширования: ${err}`));
              return networkResponse;
            })
            .catch(error => {
              log(`Ошибка загрузки ресурса: ${requestUrl.pathname} - ${error}`);
              
              // Fallback для изображений
              if (/\.(png|jpg|jpeg|gif|svg|webp)$/.test(requestUrl.pathname)) {
                return caches.match('/images/default.webp');
              }
              
              return Response.error();
            });
        })
    );
    return;
  }

  // Стратегия для навигационных запросов: Network First с fallback
  event.respondWith(
    fetch(event.request))
      .then(networkResponse => {
        // Обновляем кэш для HTML страниц
        if (networkResponse.ok && event.request.method === 'GET') {
          const responseClone = networkResponse.clone();
          caches.open(CACHE_NAME))
            .then(cache => cache.put(event.request, responseClone));
        }
        return networkResponse;
      })
      .catch(() => {
        // Для навигационных запросов возвращаем кэшированную версию
        if (event.request.mode === 'navigate') {
          return caches.match('/index.html') || caches.match(OFFLINE_URL);
        }
        
        // Для других запросов пробуем кэш
        return caches.match(event.request);
      })
  );
});

// Обработка сообщений
self.addEventListener('message', event => {
  log(`Получено сообщение от клиента: ${JSON.stringify(event.data)}`);
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    log('Получена команда SKIP_WAITING - немедленная активация');
    self.skipWaiting();
    
    // Отправляем подтверждение клиенту
    event.source.postMessage({
      type: 'RELOAD_REQUIRED'
    });
  }
  
  // Проверка версии
  if (event.data && event.data.type === 'CHECK_VERSION') {
    const clientVersion = event.data.version;
    if (clientVersion !== CACHE_VERSION) {
      log(`Несоответствие версий: клиент ${clientVersion}, SW ${CACHE_VERSION}`);
      event.source.postMessage({
        type: 'VERSION_MISMATCH',
        swVersion: CACHE_VERSION,
        clientVersion: clientVersion
      });
    }
  }
  
  // Запрос логов
  if (event.data && event.data.type === 'GET_LOGS') {
    getLogsFromDB().then(logs => {
      event.source.postMessage({
        type: 'LOGS_DATA',
        logs: logs
      });
    }).catch(error => {
      log(`Ошибка получения логов: ${error}`);
    });
  }
  
  // Очистка кэша по запросу
  if (event.data && event.data.type === 'CLEAR_CACHE') {
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== LOGS_DB_NAME) {
            log(`Очистка кэша: ${cacheName}`);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      event.source.postMessage({
        type: 'CACHE_CLEARED'
      });
    });
  }
  
  // Регистрация для push-уведомлений
  if (event.data && event.data.type === 'REGISTER_PUSH') {
    const subscription = event.data.subscription;
    log(`Регистрация для push-уведомлений`);
    
    // Сохраняем подписку в IndexedDB
    savePushSubscription(subscription)
      .then(() => {
        event.source.postMessage({
          type: 'PUSH_REGISTERED'
        });
      })
      .catch(error => {
        log(`Ошибка регистрации push: ${error}`);
        event.source.postMessage({
          type: 'PUSH_REGISTRATION_FAILED',
          error: error.message
        });
      });
  }
  
  // Запрос VAPID-ключа
  if (event.data && event.data.type === 'GET_VAPID_KEY') {
    event.source.postMessage({
      type: 'VAPID_KEY',
      key: VAPID_PUBLIC_KEY
    });
  }
});

// Сохранение push-подписки
function savePushSubscription(subscription) {
  return new Promise((resolve, reject) => {
    initDB().then(db => {
      const transaction = db.transaction('push_subscriptions', 'readwrite');
      const store = transaction.objectStore('push_subscriptions');
      
      // Проверяем существующую подписку
      const request = store.get('current');
      request.onsuccess = (e) => {
        const existing = e.target.result;
        if (existing && JSON.stringify(existing) === JSON.stringify(subscription)) {
          log('Push-подписка уже сохранена');
          resolve();
          return;
        }
        
        store.put(subscription, 'current');
        log('Push-подписка сохранена');
        resolve();
      };
      
      request.onerror = (e) => {
        log(`Ошибка при проверке подписки: ${e.target.error}`);
        store.put(subscription, 'current');
        resolve();
      };
    }).catch(reject);
  });
}

// Периодическая синхронизация
self.addEventListener('periodicsync', event => {
  if (event.tag === 'update-check') {
    log('Фоновая проверка обновлений');
    event.waitUntil(
      checkForUpdates())
        .then(() => log('Фоновая синхронизация завершена'))
        .catch(err => log(`Ошибка фоновой синхронизации: ${err}`))
    );
  }
  
  if (event.tag === 'notifications-sync') {
    log('Фоновая синхронизация уведомлений');
    event.waitUntil(
      fetch('/api/notifications'))
        .then(response => response.json())
        .then(data => {
          if (data.total > 0) {
            self.registration.showNotification('Новые уведомления', {
              body: `У вас ${data.total} новых уведомлений`,
              icon: '/images/logo.webp',
              badge: '/images/badge.webp',
              data: { url: '/family.html' }
            });
          }
        })
    );
  }
});

// Проверка обновлений в фоне
function checkForUpdates() {
  return caches.open(CACHE_NAME).then(cache => {
    return Promise.all(
      PRECACHE_RESOURCES.map(url => {
        return fetch(url, { cache: 'reload' })
          .then(response => {
            if (response.ok) {
              return cache.put(url, response);
            }
            return Promise.resolve();
          })
          .catch(() => Promise.resolve());
      })
    );
  });
}

// Обработка фоновых push-уведомлений
self.addEventListener('push', event => {
  const data = event.data.json();
  log(`Получено push-уведомление: ${data.title}`);
  
  const options = {
    body: data.body,
    icon: '/images/logo.webp',
    badge: '/images/badge.webp',
    data: {
      url: data.url || '/'
    }
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  
  // Открываем соответствующую страницу
  event.waitUntil(
    clients.openWindow(event.notification.data.url)
  );
});

// Фоновая синхронизация данных
self.addEventListener('sync', event => {
  if (event.tag === 'sync-activity') {
    log('Запуск фоновой синхронизации данных');
    event.waitUntil(
      syncRecentActivity())
    );
  }
});

// Синхронизация последней активности
function syncRecentActivity() {
  return fetch('/api/recent-activity'))
    .then(response => response.json())
    .then(data => {
      // Обновляем кэш
      return caches.open(API_CACHE_NAME))
        .then(cache => {
          const request = new Request('/api/recent-activity');
          const response = new Response(JSON.stringify(data), {
            headers: { 'Content-Type': 'application/json' }
          });
          return cache.put(request, response);
        });
    })
    .catch(error => log(`Ошибка синхронизации: ${error}`));
}

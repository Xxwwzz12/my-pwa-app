// Версия кэша
const CACHE_VERSION = 'v4.0';
const CACHE_NAME = `familyspace-cache-${CACHE_VERSION}`;
const API_CACHE_NAME = 'familyspace-api-cache-v1';
const OFFLINE_URL = '/offline.html';
const LOGS_DB_NAME = 'FamilySpace_Logs_DB';
const LOGS_STORE_NAME = 'logs';
const MAX_LOGS = 100;

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
  '/icons/icon_1.png',
  '/icons/icon-chat.png',
  '/icons/icon-calendar.png',
  '/icons/icon-profile.png',
  '/app.js',
  '/service-worker-registration.js'
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
  const isStaticResource = /\.(css|js|png|jpg|jpeg|gif|svg|ico|json)$/.test(requestUrl.pathname);
  
  log(`Запрос: ${requestUrl.pathname} [${isApiRequest ? 'API' : isStaticResource ? 'Static' : 'Navigation'}]`);
  
  // Стратегия для API запросов: Network First
  if (isApiRequest) {
    event.respondWith(
      fetch(event.request)
        .then(networkResponse => {
          // Кэшируем свежий ответ
          const responseClone = networkResponse.clone();
          caches.open(API_CACHE_NAME)
            .then(cache => cache.put(event.request, responseClone));
          return networkResponse;
        })
        .catch(() => {
          // При ошибке сети - возвращаем из кэша
          return caches.match(event.request)
            .then(cachedResponse => cachedResponse || Response.error());
        })
    );
    return;
  }

  // Стратегия для статических ресурсов: Cache First
  if (isStaticResource) {
    event.respondWith(
      caches.match(event.request)
        .then(cachedResponse => {
          // Всегда обновляем кэш в фоне
          const fetchPromise = fetch(event.request).then(networkResponse => {
            // Обновляем кэш
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, networkResponse.clone());
            });
            return networkResponse;
          }).catch(() => {}); // Игнорируем ошибки сетевого запроса
          
          // Возвращаем кэшированный ответ или пробуем сеть
          return cachedResponse || fetchPromise;
        })
    );
    return;
  }

  // Стратегия для навигационных запросов: Network First с fallback
  event.respondWith(
    fetch(event.request)
      .catch(() => {
        // Для навигационных запросов возвращаем offline.html
        if (event.request.mode === 'navigate') {
          return caches.match(OFFLINE_URL);
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
});

// Периодическая синхронизация
self.addEventListener('periodicsync', event => {
  if (event.tag === 'update-check') {
    log('Фоновая проверка обновлений');
    event.waitUntil(
      caches.open(CACHE_NAME).then(cache => {
        return cache.addAll(PRECACHE_RESOURCES.map(url => {
          return new Request(url, { cache: 'reload' });
        }));
      })
      .then(() => log('Фоновая синхронизация завершена'))
      .catch(err => log(`Ошибка фоновой синхронизации: ${err}`))
    );
  }
});

// Обработка фоновых push-уведомлений
self.addEventListener('push', event => {
  const data = event.data.json();
  log(`Получено push-уведомление: ${data.title}`);
  
  const options = {
    body: data.body,
    icon: '/icons/icon_1.png',
    badge: '/icons/icon_1.png',
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
  event.waitUntil(
    clients.openWindow(event.notification.data.url)
  );
});

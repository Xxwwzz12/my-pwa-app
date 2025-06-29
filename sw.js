// Версия кэша
const CACHE_NAME = 'ai-assistant-cache-v3.0';
const OFFLINE_URL = '/offline.html';
const LOGS_DB_NAME = 'SW_Logs_DB';
const LOGS_STORE_NAME = 'logs';
const MAX_LOGS = 100;

// Улучшенная система логов с IndexedDB
function log(message) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] ${message}`;
  
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
        return cache.addAll([
          '/',
          '/index.html',
          '/chat.html',
          '/offline.html',
          '/manifest.json',
          '/icon-192.png',
          '/icon-512.png'
        ]);
      })
      .catch(error => {
        log(`Ошибка при установке: ${error.message}`);
      })
  );
});

// Активация Service Worker
self.addEventListener('activate', event => {
  log('Активация Service Worker');
  
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      log(`Найдено кэшей: ${cacheNames.length}`);
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
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
            version: CACHE_NAME.split('-').pop()
          });
        });
      });
    })
  );
});

// Стратегия работы с запросами
self.addEventListener('fetch', event => {
  log(`Запрос: ${event.request.url}`);
  
  // Для навигационных запросов используем другую стратегию
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .catch(() => {
          log('Оффлайн режим, показ offline.html');
          return caches.match(OFFLINE_URL);
        })
    );
    return;
  }

  // Стандартная стратегия для остальных запросов
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Клонируем ответ для кэширования
        const responseToCache = response.clone();
        caches.open(CACHE_NAME)
          .then(cache => {
            log(`Кэширование: ${event.request.url}`);
            cache.put(event.request, responseToCache);
          });
        return response;
      })
      .catch(() => {
        // При ошибке сети - возвращаем из кэша
        log(`Ошибка сети, поиск в кэше: ${event.request.url}`);
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
      type: 'UPDATE_CONFIRMED',
      version: CACHE_NAME
    });
  }
  
  // Запрос логов из IndexedDB
  if (event.data && event.data.type === 'GET_LOGS') {
    getLogsFromDB().then(logs => {
      event.source.postMessage({
        type: 'SW_LOGS_RESPONSE',
        logs: logs
      });
    }).catch(error => {
      log(`Ошибка получения логов: ${error.message}`);
    });
  }
  
  // Очистка логов
  if (event.data && event.data.type === 'CLEAR_LOGS') {
    initDB().then(db => {
      const transaction = db.transaction(LOGS_STORE_NAME, 'readwrite');
      const store = transaction.objectStore(LOGS_STORE_NAME);
      store.clear();
      log('Логи Service Worker очищены');
    });
  }
});

// Периодическая синхронизация (для фоновых обновлений)
self.addEventListener('periodicsync', event => {
  if (event.tag === 'check-updates') {
    log('Периодическая проверка обновлений');
    event.waitUntil(
      self.registration.update()
        .then(() => log('Проверка обновлений завершена'))
        .catch(err => log(`Ошибка проверки обновлений: ${err.message}`))
    );
  }
});

// Фоновая синхронизация
self.addEventListener('sync', event => {
  if (event.tag === 'update-sync') {
    log('Запуск фоновой синхронизации обновлений');
    event.waitUntil(
      self.registration.update()
        .then(() => log('Фоновая синхронизация завершена'))
        .catch(err => log(`Ошибка фоновой синхронизации: ${err.message}`))
    );
  }
});
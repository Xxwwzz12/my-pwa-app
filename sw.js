// Увеличиваем версию кэша
const CACHE_NAME = 'ai-assistant-cache-v2.4'; // ИЗМЕНИТЕ ВЕРСИЮ!
const OFFLINE_URL = '/offline.html';

// Логирование в Service Worker
function log(message) {
  console.log(`[ServiceWorker] ${message}`);
  
  // Отправляем логи на клиент
  self.clients.matchAll().then(clients => {
    clients.forEach(client => {
      client.postMessage({
        type: 'SW_LOG',
        message: `[SW] ${message}`
      });
    });
  });
}

// Установка
self.addEventListener('install', event => {
  log(`Установка новой версии: ${CACHE_NAME}`);
  
  // Пропускаем ожидание для немедленной активации
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
          '/styles.css',
          '/icon-192.png'
        ]);
      })
  );
});

// Активация
self.addEventListener('activate', event => {
  log('Активация Service Worker');
  
  const cacheWhitelist = [CACHE_NAME];
  
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
  );
  
  // Сообщаем клиентам о новой версии
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then(clients => {
      clients.forEach(client => {
        log(`Отправка NEW_VERSION_AVAILABLE клиенту: ${client.url}`);
        client.postMessage({
          type: 'NEW_VERSION_AVAILABLE',
          version: CACHE_NAME.split('-').pop() // Извлекаем версию из имени кэша
        });
      });
    })
  );
});

// Обработка запросов
self.addEventListener('fetch', event => {
  // Для навигационных запросов
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .catch(() => {
          log('Показ оффлайн страницы');
          return caches.match(OFFLINE_URL);
        })
    );
  } else {
    // Для остальных запросов
    event.respondWith(
      caches.match(event.request)
        .then(response => {
          return response || fetch(event.request);
        })
    );
  }
});

// Обработка сообщений
self.addEventListener('message', event => {
  log(`Получено сообщение от клиента: ${JSON.stringify(event.data)}`);
  
  if (event.data === 'SKIP_WAITING') {
    log('Получена команда SKIP_WAITING');
    self.skipWaiting();
  }
});
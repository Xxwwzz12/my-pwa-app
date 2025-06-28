// Увеличиваем версию кэша
const CACHE_NAME = 'ai-assistant-cache-v2.4';
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
          '/icon-192.png'
        ]);
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
  );
  
  // Сообщаем клиентам о новой версии
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then(clients => {
      clients.forEach(client => {
        log(`Отправка NEW_VERSION_AVAILABLE клиенту: ${client.url}`);
        client.postMessage({
          type: 'NEW_VERSION_AVAILABLE',
          version: CACHE_NAME.split('-').pop()
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
});
// Версия кэша
const CACHE_NAME = 'ai-assistant-cache-v2.3';
const OFFLINE_URL = '/offline.html';

// Логирование в Service Worker
function log(message) {
  console.log(`[ServiceWorker] ${message}`);
}

// Установка
self.addEventListener('install', event => {
  log('Установка новой версии');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        log('Кэширование основных ресурсов');
        return cache.addAll([
          '/',
          '/index.html',
          '/offline.html',
          '/icon-192.png'
        ]);
      })
  );
});

// Активация
self.addEventListener('activate', event => {
  log('Активация Service Worker');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            log(`Удаление старого кэша: ${cacheName}`);
            return caches.delete(cacheName);
          }
        })
      );
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
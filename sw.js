// Service Worker для кэширования ресурсов
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open('pwa-cache-v1').then(cache => {
      return cache.addAll([
        '/',
        '/index.html',
        // Добавьте сюда другие файлы: CSS, JS, изображения
      ]);
    })
  );
});

// Стратегия: сначала из кэша, потом сеть
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});
// ===== Service Worker для FamilySpace PWA (v5.5.0) =====
const CACHE_VERSION = 'v5.5.0';
const CACHE_NAME = `familyspace-cache-${CACHE_VERSION}`;
const API_CACHE_NAME = 'familyspace-api-cache-v4';
const IMAGE_CACHE_NAME = 'image-cache-v2';
const OFFLINE_URL = '/offline.html';
const VAPID_PUBLIC_KEY = self.__VAPID_PUBLIC_KEY; // Инжектируется при регистрации
const SYNC_QUEUE = "sync-queue";
const MAX_API_CACHE_ENTRIES = 100; // #108 - ограничение размера кэша

// Ресурсы для предварительного кэширования
const PRECACHE_RESOURCES = [
  '/',
  '/index.html',
  '/offline.html',
  '/style.css',
  '/manifest.json',
  '/images/assets/logo.webp',
  '/images/assets/default.webp',
  '/js/api.js',
  '/js/auth.js'
];

// Эндпоинты без кэширования
const NO_CACHE_ENDPOINTS = [
  '/api/save-subscription',
  '/api/send-push',
  '/api/auth',
  '/api/save-data'
];

// Улучшенное логирование с отправкой на сервер
async function log(message, level = 'info') {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] SW v${CACHE_VERSION}: ${message}`;
  
  console[level](logEntry);
  
  // Отправка логов на сервер для мониторинга (#205)
  try {
    await fetch('/api/sw-logs', {
      method: 'POST',
      body: JSON.stringify({
        message: logEntry,
        level,
        version: CACHE_VERSION
      }),
      headers: {
        'Content-Type': 'application/json'
      }
    });
  } catch (error) {
    console.error('Ошибка отправки лога:', error);
  }
}

// Глобальная обработка ошибок (#205)
self.addEventListener('error', event => {
  log(`Глобальная ошибка: ${event.message} ${event.filename}:${event.lineno}`, 'error');
});

self.addEventListener('unhandledrejection', event => {
  log(`Необработанный rejection: ${event.reason}`, 'error');
});

// Инициализация базы данных для синхронизации
async function initSyncDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(SYNC_QUEUE, 2);
    
    request.onerror = () => reject('Ошибка инициализации IndexedDB');
    
    request.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('requests')) {
        const store = db.createObjectStore('requests', { keyPath: 'id', autoIncrement: true });
        store.createIndex('url', 'url', { unique: false });
      }
    };
    
    request.onsuccess = e => resolve(e.target.result);
  });
}

// Установка Service Worker
self.addEventListener('install', event => {
  log(`Установка новой версии: ${CACHE_NAME}`);
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_RESOURCES))
      .then(() => self.skipWaiting())
      .catch(error => {
        log(`Ошибка установки: ${error.message}`, 'error');
      })
  );
});

// Активация Service Worker
self.addEventListener('activate', event => {
  log(`Активация версии ${CACHE_VERSION}`);
  
  const cacheWhitelist = [CACHE_NAME, API_CACHE_NAME, IMAGE_CACHE_NAME];
  
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
      .then(() => self.clients.claim()) // #156 - немедленный контроль
      .then(() => {
        log('Активация завершена');
        self.clients.matchAll({ type: 'window' }).then(clients => {
          clients.forEach(client => {
            client.postMessage({
              type: 'SW_ACTIVATED',
              version: CACHE_VERSION
            });
          });
        });
      })
  );
});

// Проверка необходимости кэширования API
function shouldCacheApi(pathname) {
  return pathname.startsWith('/api/') && 
         !NO_CACHE_ENDPOINTS.some(endpoint => pathname.startsWith(endpoint));
}

// Обработчик запросов
self.addEventListener('fetch', event => {
  const requestUrl = new URL(event.request.url);
  const pathname = requestUrl.pathname;
  
  // Пропускаем не-GET запросы и исключенные эндпоинты
  if (event.request.method !== 'GET' || 
      NO_CACHE_ENDPOINTS.some(endpoint => pathname.startsWith(endpoint))) {
    return fetch(event.request);
  }
  
  const isApiRequest = shouldCacheApi(pathname);
  const isNavigation = /\.(html?)$/.test(pathname);
  const isImage = /\.(png|jpg|jpeg|gif|svg|webp)$/.test(pathname);
  const isStatic = /\.(css|js|ico|json)$/.test(pathname);
  
  // #158 - Revalidation для HTML
  if (isNavigation) {
    event.respondWith(handleNavigationRequest(event));
    return;
  }
  
  if (isApiRequest) {
    event.respondWith(handleApiRequest(event));
    return;
  }
  
  if (isImage) {
    event.respondWith(handleImageRequest(event));
    return;
  }
  
  if (isStatic) {
    event.respondWith(handleStaticRequest(event));
    return;
  }
  
  // Для неизвестных типов - сетевое взаимодействие
  event.respondWith(fetch(event.request));
});

// Обработка API запросов с ограничением кэша (#108)
async function handleApiRequest(event) {
  try {
    const response = await fetchWithTimeout(event.request, 3000);
    
    // Кэшируем успешные ответы
    if (response.ok) {
      const cache = await caches.open(API_CACHE_NAME);
      
      // Проверка и ограничение размера кэша
      const keys = await cache.keys();
      if (keys.length >= MAX_API_CACHE_ENTRIES) {
        await cache.delete(keys[0]); // LRU стратегия
        log(`Удалена старая запись API кэша (макс. ${MAX_API_CACHE_ENTRIES})`);
      }
      
      await cache.put(event.request, response.clone());
    }
    
    return response;
  } catch (error) {
    log(`Сбой сети для API: ${error.message}`, 'warn');
    
    // Пытаемся вернуть данные из кэша
    const cachedResponse = await caches.match(event.request);
    if (cachedResponse) return cachedResponse;
    
    // Общий fallback для API
    return fallbackApiResponse(event.request);
  }
}

// Revalidation для навигационных запросов (#158)
async function handleNavigationRequest(event) {
  // Сначала пытаемся получить из кэша
  const cachedResponse = await caches.match(event.request);
  
  // Фоновая проверка обновлений
  if (cachedResponse) {
    event.waitUntil(
      fetch(event.request)
        .then(async response => {
          if (response.ok) {
            const cache = await caches.open(CACHE_NAME);
            await cache.put(event.request, response);
          }
        })
        .catch(() => { /* Игнорируем ошибки фонового обновления */ })
    );
    return cachedResponse;
  }
  
  // Если нет в кэше - сетевой запрос
  try {
    const response = await fetch(event.request);
    
    // Кэшируем успешные ответы
    if (response.ok) {
      const clone = response.clone();
      caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
    }
    
    return response;
  } catch (error) {
    log(`Ошибка навигации: ${error.message}`, 'warn');
    
    // Возвращаем offline-страницу
    const offlinePage = await caches.match(OFFLINE_URL);
    if (offlinePage) return offlinePage;
    
    // Fallback для корневой страницы
    return caches.match('/index.html');
  }
}

// Обработка запросов изображений
async function handleImageRequest(event) {
  try {
    const cache = await caches.open(IMAGE_CACHE_NAME);
    const cachedResponse = await cache.match(event.request);
    
    if (cachedResponse) return cachedResponse;
    
    const response = await fetch(event.request);
    
    if (response.ok) {
      // LRU стратегия (макс. 50 изображений)
      const keys = await cache.keys();
      if (keys.length > 50) {
        await cache.delete(keys[0]);
        log('Очищен старый элемент из кэша изображений');
      }
      
      cache.put(event.request, response.clone());
    }
    
    return response;
  } catch (error) {
    return caches.match('/images/assets/default.webp');
  }
}

// Обработка статических запросов
async function handleStaticRequest(event) {
  const cachedResponse = await caches.match(event.request);
  if (cachedResponse) return cachedResponse;
  
  try {
    const response = await fetch(event.request);
    
    if (response.ok) {
      const clone = response.clone();
      caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
    }
    
    return response;
  } catch (error) {
    log(`Ошибка загрузки ресурса: ${event.request.url} - ${error.message}`, 'warn');
    return Response.error();
  }
}

// Обработчик push-уведомлений
self.addEventListener('push', event => {
  try {
    const payload = event.data?.json() || {};
    const { title = 'FamilySpace', body = 'Новое уведомление', url = '/', icon, badge } = payload;
    
    event.waitUntil(
      self.registration.showNotification(title, {
        body,
        icon: icon || '/images/assets/logo.webp',
        badge: badge || '/images/assets/badge.webp',
        data: { url },
        vibrate: [200, 100, 200]
      })
    );
    
    log(`Push уведомление: "${title}"`);
  } catch (error) {
    log(`Ошибка обработки push: ${error.message}`, 'error');
  }
});

// Обработчик кликов по уведомлениям
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data.url || '/';
  
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(clients => {
      const target = clients.find(c => c.url === url);
      return target ? target.focus() : clients.openWindow(url);
    })
  );
});

// Сохранение в очередь синхронизации с повторными попытками (#175)
async function saveToSyncQueue(request) {
  const MAX_RETRIES = 3;
  let attempt = 0;
  
  const requestData = {
    url: request.url,
    method: request.method,
    headers: Array.from(request.headers.entries()),
    body: await request.clone().text(),
    timestamp: Date.now()
  };
  
  while (attempt < MAX_RETRIES) {
    try {
      const db = await initSyncDB();
      const tx = db.transaction('requests', 'readwrite');
      const store = tx.objectStore('requests');
      await store.add(requestData);
      return true;
    } catch (error) {
      attempt++;
      log(`Ошибка сохранения в очередь (попытка ${attempt}): ${error}`, 'warn');
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
  
  log(`Не удалось сохранить в очередь: ${request.url}`, 'error');
  return false;
}

// Фоновая синхронизация (#257)
self.addEventListener('sync', event => {
  if (event.tag === 'sync-data') {
    log(`Запуск фоновой синхронизации`);
    event.waitUntil(processSyncQueue());
  }
});

async function processSyncQueue() {
  try {
    const db = await initSyncDB();
    const tx = db.transaction('requests', 'readwrite');
    const store = tx.objectStore('requests');
    const requests = await store.getAll();
    
    for (const item of requests) {
      try {
        const { url, method, headers, body } = item;
        const request = new Request(url, {
          method,
          headers: new Headers(headers),
          body: method !== 'GET' ? body : null
        });
        
        const response = await fetch(request);
        if (response.ok) {
          await store.delete(item.id);
          log(`Синхронизировано: ${url}`);
        }
      } catch (error) {
        log(`Ошибка синхронизации ${item.url}: ${error}`, 'warn');
      }
    }
  } catch (error) {
    log(`Ошибка обработки очереди: ${error}`, 'error');
  }
}

// Обработчик POST-запросов для синхронизации
self.addEventListener('fetch', event => {
  if (event.request.method === 'POST' && 
      event.request.url.includes('/api/save-data')) {
    event.respondWith(
      (async () => {
        try {
          const response = await fetch(event.request.clone());
          return response;
        } catch (error) {
          const saved = await saveToSyncQueue(event.request);
          return new Response(JSON.stringify({ 
            status: saved ? 'queued' : 'error',
            message: saved ? 'Данные сохранены для синхронизации' : 'Ошибка сохранения'
          }), {
            status: saved ? 202 : 500,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      })()
    );
  }
});

// Обработчик сообщений
self.addEventListener('message', event => {
  if (!event.data) return;
  
  switch (event.data.type) {
    case 'SKIP_WAITING':
      self.skipWaiting();
      break;
      
    case 'GET_VAPID_KEY':
      event.source.postMessage({ 
        type: 'VAPID_KEY',
        key: VAPID_PUBLIC_KEY
      });
      break;
      
    case 'CLEAR_CACHE':
      caches.keys().then(cacheNames => {
        Promise.all(cacheNames.map(cacheName => caches.delete(cacheName)))
          .then(() => event.source.postMessage({ type: 'CACHE_CLEARED' }));
      });
      break;
      
    case 'TRIGGER_SYNC':
      event.waitUntil(processSyncQueue());
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
// public/utils/cache-strategy.js
import db from '../db-instance.js'; // Централизованный экземпляр БД

// Утилиты для повторных попыток
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const calculateDelay = (attempt, delayType) => {
  switch (delayType) {
    case 'linear':
      return 1000 * attempt;
    case 'exponential':
      return 1000 * Math.pow(2, attempt - 1);
    default:
      return 1000;
  }
};

const withRetry = async (fn, retryPolicy) => {
  const { attempts = 3, delay: delayType = 'exponential' } = retryPolicy || {};
  let lastError;
  
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        const waitTime = calculateDelay(attempt, delayType);
        await delay(waitTime);
      }
    }
  }
  throw lastError;
};

// Основные стратегии кэширования
export async function staleWhileRevalidate(key, fetchFn, options = {}) {
  const {
    cacheName = 'cache',
    maxAge = 300,
    shouldCache = (response) => response?.ok,
    matchOptions,
    retryPolicy
  } = options;

  // Чтение из кэша
  const cacheKey = JSON.stringify({ key, matchOptions });
  let cached = null;
  
  try {
    cached = await db.get(cacheName, cacheKey);
  } catch (error) {
    console.error(`Cache read error for ${key}:`, error);
  }

  const now = Date.now();
  let isStale = false;

  if (cached) {
    isStale = (now - cached.timestamp) > maxAge * 1000;
    if (!isStale) {
      // Фоновое обновление для свежих данных
      updateCacheInBackground();
      return cached.data;
    }
  }

  // Обновление кэша при устаревших данных
  async function updateCacheInBackground() {
    try {
      const response = await withRetry(fetchFn, retryPolicy);
      if (shouldCache(response)) {
        try {
          await db.set(cacheName, { 
            id: cacheKey, 
            data: response,
            timestamp: Date.now()
          });
        } catch (dbError) {
          console.error(`Cache write error for ${key}:`, dbError);
        }
      }
    } catch (error) {
      console.error(`Background update failed for ${key}:`, error);
      // Отправка метрик в аналитику
      if (window.trackError) {
        window.trackError('CACHE_UPDATE_ERROR', {
          key,
          error: error.message
        });
      }
    }
  }

  // Параллельное обновление кэша
  updateCacheInBackground();

  if (cached) return cached.data;
  
  // Первоначальный запрос при отсутствии кэша
  try {
    const response = await withRetry(fetchFn, retryPolicy);
    if (shouldCache(response)) {
      try {
        await db.set(cacheName, { 
          id: cacheKey, 
          data: response,
          timestamp: Date.now()
        });
      } catch (dbError) {
        console.error(`Cache write error for ${key}:`, dbError);
      }
    }
    return response;
  } catch (error) {
    if (cached) {
      console.warn(`Using stale data after fetch error for ${key}`);
      return cached.data;
    }
    throw error;
  }
}

export async function cacheFirst(key, fetchFn, options = {}) {
  const {
    cacheName = 'cache',
    maxAge = 300,
    shouldCache = (response) => response?.ok,
    matchOptions,
    retryPolicy
  } = options;

  const cacheKey = JSON.stringify({ key, matchOptions });
  let cached = null;
  
  try {
    cached = await db.get(cacheName, cacheKey);
  } catch (error) {
    console.error(`Cache read error for ${key}:`, error);
  }

  const now = Date.now();

  if (cached && (now - cached.timestamp) <= maxAge * 1000) {
    return cached.data;
  }

  try {
    const response = await withRetry(fetchFn, retryPolicy);
    if (shouldCache(response)) {
      try {
        await db.set(cacheName, { 
          id: cacheKey, 
          data: response,
          timestamp: Date.now()
        });
      } catch (dbError) {
        console.error(`Cache write error for ${key}:`, dbError);
      }
    }
    return response;
  } catch (error) {
    if (cached) {
      console.warn(`Using cached data after fetch error for ${key}`);
      return cached.data;
    }
    throw error;
  }
}

// Управление жизненным циклом кэша
export class CacheManager {
  constructor() {
    this.strategies = new Map();
  }

  addStrategy(key, strategy) {
    if (typeof strategy !== 'function') {
      throw new Error('Strategy must be a function');
    }
    this.strategies.set(key, strategy);
  }

  async execute(key, ...args) {
    const strategy = this.strategies.get(key);
    if (!strategy) {
      throw new Error(`Strategy not found for key: ${key}`);
    }
    return strategy(...args);
  }
}

// Интеграция с Service Worker
export function registerCacheRoutes(workbox) {
  if (!workbox) return;

  // Стратегия SWR для API-запросов
  workbox.registerRoute(
    ({ url }) => url.pathname.startsWith('/api/'),
    new workbox.strategies.StaleWhileRevalidate({
      cacheName: 'api-cache',
      plugins: [
        {
          cacheWillUpdate: async ({ response }) => {
            return response.ok ? response : null;
          }
        }
      ]
    })
  );

  // Стратегия Cache-First для статических ресурсов
  workbox.registerRoute(
    ({ request }) => ['style', 'script', 'image'].includes(request.destination),
    new workbox.strategies.CacheFirst({
      cacheName: 'static-assets',
      plugins: [
        new workbox.ExpirationPlugin({
          maxEntries: 100,
          maxAgeSeconds: 30 * 24 * 60 * 60, // 30 дней
        }),
      ],
    })
  );
}
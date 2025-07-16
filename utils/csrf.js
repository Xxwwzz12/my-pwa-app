// public/utils/csrf.js

// Конфигурация
const csrfConfig = {
  tokenEndpoint: '/api/csrf-token',
  storageKey: 'csrfToken',
  headerName: 'CSRF-Token'
};

// Состояние модуля
let isInitialized = false;
let isRefreshing = false;
let refreshQueue = [];

// 1. Инициализация CSRF токена
export async function initCsrf() {
  if (isInitialized) return;
  
  try {
    const response = await fetch(csrfConfig.tokenEndpoint, {
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error(`CSRF init failed: ${response.status}`);
    }
    
    const data = await response.json();
    localStorage.setItem(csrfConfig.storageKey, data.token);
    isInitialized = true;
    
    return data.token;
  } catch (error) {
    console.error('CSRF initialization error:', error);
    throw error;
  }
}

// 2. Получение токена из localStorage
export function getCsrfToken() {
  return localStorage.getItem(csrfConfig.storageKey);
}

// 3. Обертка для fetch с автоматическим CSRF
export async function fetchWithCsrf(url, options = {}) {
  // Автоматическая инициализация при первом вызове
  if (!isInitialized) {
    await initCsrf();
  }

  const method = options.method?.toUpperCase() || 'GET';
  const requiresCsrf = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);

  // Подготовка запроса
  const headers = new Headers(options.headers || {});
  
  if (requiresCsrf) {
    const token = getCsrfToken();
    
    if (!token) {
      console.error('CSRF token missing for protected method');
      throw new Error('CSRF token required');
    }
    
    headers.set(csrfConfig.headerName, token);
  }

  // Выполнение запроса
  let response = await fetch(url, {
    ...options,
    headers
  });

  // Обработка устаревшего токена
  if (response.status === 419) {
    return handleTokenExpiry(() => fetchWithCsrf(url, options));
  }

  return response;
}

// 4. Обработка устаревших токенов
async function handleTokenExpiry(retry) {
  // Если уже обновляем - добавляем в очередь
  if (isRefreshing) {
    return new Promise((resolve) => {
      refreshQueue.push(resolve);
    }).then(retry);
  }

  try {
    isRefreshing = true;
    
    // Обновляем токен
    const newToken = await refreshCsrf();
    localStorage.setItem(csrfConfig.storageKey, newToken);
    
    // Повторяем запрос
    const result = await retry();
    
    // Выполняем запросы из очереди
    flushRefreshQueue();
    
    return result;
  } catch (error) {
    console.error('Token refresh failed:', error);
    throw error;
  } finally {
    isRefreshing = false;
  }
}

// 5. Обновление CSRF токена
async function refreshCsrf() {
  try {
    const response = await fetch(csrfConfig.tokenEndpoint, {
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error(`Refresh failed: ${response.status}`);
    }
    
    const data = await response.json();
    return data.token;
  } catch (error) {
    console.error('CSRF refresh error:', error);
    throw error;
  }
}

// 6. Очистка очереди запросов
function flushRefreshQueue() {
  while (refreshQueue.length) {
    const resolve = refreshQueue.shift();
    resolve();
  }
}

// 7. Конфигурирование (опционально)
export function configureCsrf(config) {
  Object.assign(csrfConfig, config);
}
// public/utils/csrf.js

// Конфигурация модуля
let csrfConfig = {
  refreshURL: '/refresh-csrf',
  refreshMethod: 'GET',
  updateToken: defaultUpdateToken
};

// 1. Получение токена из мета-тега
export function getCSRFToken() {
  const metaTag = document.querySelector('meta[name="csrf-token"]');
  return metaTag ? metaTag.content : null;
}

// 2. Установка нового токена в DOM
function setCSRFToken(token) {
  let metaTag = document.querySelector('meta[name="csrf-token"]');
  
  if (!metaTag) {
    metaTag = document.createElement('meta');
    metaTag.name = 'csrf-token';
    document.head.appendChild(metaTag);
  }
  
  metaTag.content = token;
}

// 3. Обертка для fetch с обработкой CSRF
let isRefreshing = false;
let refreshPromise = null;

export async function fetchWithCSRF(url, options = {}) {
  const token = getCSRFToken();
  if (!token) console.warn('CSRF token not found!');

  // Подготавливаем заголовки
  const headers = new Headers(options.headers || {});
  if (token) {
    headers.set('X-CSRF-Token', token);
  }

  // Первоначальный запрос
  let response = await fetch(url, {
    ...options,
    headers
  });

  // Обработка ошибки CSRF (419)
  if (response.status === 419) {
    try {
      if (!isRefreshing) {
        isRefreshing = true;
        refreshPromise = refreshCSRF()
          .finally(() => {
            isRefreshing = false;
            refreshPromise = null;
          });
      }

      await refreshPromise;

      // Повторяем запрос с новым токеном
      const newToken = getCSRFToken();
      if (newToken) {
        headers.set('X-CSRF-Token', newToken);
      }
      
      response = await fetch(url, {
        ...options,
        headers
      });
    } catch (refreshError) {
      console.error('CSRF refresh failed:', refreshError);
      return response; // Возвращаем исходную ошибку 419
    }
  }

  return response;
}

// 4. Обновление CSRF токена
export async function refreshCSRF() {
  try {
    const response = await fetch(csrfConfig.refreshURL, {
      method: csrfConfig.refreshMethod,
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error(`Refresh failed with status ${response.status}`);
    }

    const newToken = await csrfConfig.updateToken(response);
    if (!newToken) {
      throw new Error('No CSRF token received');
    }

    setCSRFToken(newToken);
    return newToken;
  } catch (error) {
    console.error('CSRF refresh error:', error);
    throw error;
  }
}

// 5. Функция по умолчанию для извлечения токена
async function defaultUpdateToken(response) {
  const contentType = response.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    const data = await response.json();
    return data.csrfToken || data.token;
  }

  if (contentType.includes('text/html')) {
    const text = await response.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, 'text/html');
    const meta = doc.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : null;
  }

  return null;
}

// 6. Конфигурирование модуля
export function configureCSRF(config) {
  Object.assign(csrfConfig, config);
}

// 7. Инициализация (опционально)
export function initCSRF() {
  if (!getCSRFToken()) {
    console.warn('CSRF token meta tag is missing. Creating default...');
    setCSRFToken('');
  }
}
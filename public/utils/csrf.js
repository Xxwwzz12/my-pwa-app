// public/utils/csrf.js

// Конфигурация модуля
let csrfConfig = {
  refreshURL: '/refresh-csrf',
  refreshMethod: 'GET'
};

// 1. Получение токена из куки
export function getCsrfToken() {
  const match = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

// 2. Обертка для fetch с обработкой CSRF
let isRefreshing = false;
let refreshPromise = null;

export async function fetchWithCsrf(url, options = {}) {
  const token = getCsrfToken();
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
      const newToken = getCsrfToken();
      if (newToken) {
        headers.set('X-CSRF-Token', newToken);
      } else {
        console.warn('CSRF token still missing after refresh');
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

// 3. Обновление CSRF токена
export async function refreshCSRF() {
  try {
    const response = await fetch(csrfConfig.refreshURL, {
      method: csrfConfig.refreshMethod,
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error(`Refresh failed with status ${response.status}`);
    }

    // Кука автоматически устанавливается браузером
    return true;
  } catch (error) {
    console.error('CSRF refresh error:', error);
    throw error;
  }
}

// 4. Конфигурирование модуля
export function configureCsrf(config) {
  Object.assign(csrfConfig, config);
}
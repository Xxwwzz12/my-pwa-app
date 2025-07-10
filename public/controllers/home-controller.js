import { fetchWithCSRF } from '../utils/csrf.js';
import { staleWhileRevalidate } from '../utils/cache-strategy.js';

export default function HomeController() {
  let eventListeners = [];
  
  // Загрузка данных с кешированием по стратегии SWR
  async function loadData() {
    try {
      const response = await staleWhileRevalidate(
        'home-data',
        () => fetchWithCSRF('/api/home'),
        { maxAge: 300, cacheName: 'home' }
      );
      
      if (!response.ok) {
        throw new Error(`Ошибка загрузки: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Ошибка в loadData:', error);
      return {
        user: { name: 'Гость' },
        family: { name: 'Неизвестная семья' },
        unreadMessages: 0,
        features: []
      };
    }
  }

  // Рендеринг домашней страницы
  function render(data) {
    const container = document.getElementById('home-container');
    if (!container) return;

    container.innerHTML = `
      <div class="dashboard">
        <div class="stats">
          <h2>Добро пожаловать, ${data.user.name}!</h2>
          <p>Семья: ${data.family.name}</p>
          <p>Новых сообщений: ${data.unreadMessages}</p>
        </div>
        
        <div class="notifications">
          ${data.notifications && data.notifications.length > 0 
            ? `<h3>Уведомления</h3>
               <div class="notification-list">
                 ${data.notifications.map(n => `
                   <div class="notification ${n.important ? 'important' : ''}">
                     <span>${n.message}</span>
                   </div>
                 `).join('')}
               </div>`
            : '<p>Нет новых уведомлений</p>'}
        </div>
        
        <div class="quick-links">
          <h3>Быстрый доступ</h3>
          <div class="features-grid">
            ${data.features.map(feature => `
              <a href="${feature.link}" 
                 data-action="${feature.action}" 
                 class="feature-card">
                <i class="${feature.icon}"></i>
                <span>${feature.title}</span>
              </a>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }

  // Трекинг действий для аналитики
  function trackAnalytics(action) {
    console.log(`[Analytics] Action: ${action}`);
    // Реальная реализация отправки данных в аналитику
    // analytics.track('feature_click', { action });
  }

  // Привязка обработчиков событий
  function attachEvents() {
    const cards = document.querySelectorAll('.feature-card');
    cards.forEach(card => {
      const handler = (e) => {
        e.preventDefault();
        trackAnalytics(card.dataset.action);
        
        // Навигация с обработкой SPA роутера
        if (window.router) {
          window.router.navigate(card.getAttribute('href'));
        } else {
          window.location.href = card.getAttribute('href');
        }
      };
      
      card.addEventListener('click', handler);
      eventListeners.push(() => card.removeEventListener('click', handler));
    });
  }

  // Очистка ресурсов
  function cleanup() {
    eventListeners.forEach(cleanup => cleanup());
    eventListeners = [];
  }

  return {
    init: async () => {
      try {
        const data = await loadData();
        render(data);
        attachEvents();
      } catch (e) {
        console.error('Ошибка инициализации HomeController:', e);
        document.getElementById('home-container').innerHTML = `
          <div class="error">
            <h2>Ошибка загрузки данных</h2>
            <p>${e.message}</p>
            <button id="retry-load">Повторить попытку</button>
          </div>
        `;
        document.getElementById('retry-load')?.addEventListener('click', this.init);
      }
    },
    cleanup
  };
}
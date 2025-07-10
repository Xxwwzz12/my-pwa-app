import { fetchWithCSRF } from '../utils/csrf.js';
import { staleWhileRevalidate } from '../utils/cache-strategy.js';

export default function FamilyController(familyId) {
  let eventListeners = [];
  
  async function loadData() {
    return staleWhileRevalidate(
      `family-${familyId}`,
      () => fetchWithCSRF(`/api/family/${familyId}`),
      { cacheName: 'families', maxAge: 600 }
    );
  }

  function render(data) {
    const container = document.getElementById('family-container');
    if (!container) {
      console.error('Container element not found');
      return;
    }

    container.innerHTML = `
      <h2>${data.name}</h2>
      <div class="family-meta">
        <span>ID: ${data.id}</span>
        <span>Members: ${data.memberCount}</span>
        <span>Created: ${new Date(data.createdAt).toLocaleDateString()}</span>
      </div>
      <div class="members-list">
        ${data.members.map(m => `
          <div class="member-card" data-member-id="${m.id}">
            <h3>${m.name}</h3>
            <p>Age: ${m.age}</p>
            <p>Role: ${m.role}</p>
          </div>
        `).join('')}
      </div>
    `;

    // Добавляем обработчики событий
    const memberCards = container.querySelectorAll('.member-card');
    memberCards.forEach(card => {
      const handler = () => handleMemberClick(card.dataset.memberId);
      card.addEventListener('click', handler);
      eventListeners.push(() => card.removeEventListener('click', handler));
    });
  }

  function handleMemberClick(memberId) {
    console.log('Member selected:', memberId);
    // Здесь будет логика обработки клика
  }

  function cleanup() {
    eventListeners.forEach(unsubscribe => unsubscribe());
    eventListeners = [];
  }

  return {
    init: async () => {
      try {
        const response = await loadData();
        const data = await response.json();
        render(data);
      } catch (error) {
        const container = document.getElementById('family-container');
        if (container) {
          container.innerHTML = `<div class="error">${error.message}</div>`;
        }
        console.error('Initialization failed:', error);
      }
    },
    cleanup
  };
}
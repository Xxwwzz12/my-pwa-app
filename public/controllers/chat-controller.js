// public/controllers/chat-controller.js
import db from '../db-instance.js';
import { fetchWithCSRF } from '../utils/csrf.js';

export default function ChatController(chatId) {
  // Элементы DOM
  const chatForm = document.getElementById('chat-form');
  const messageInput = document.getElementById('message-input');
  const messagesContainer = document.getElementById('messages-container');
  const sendButton = document.getElementById('send-button');

  // WebSocket соединение
  let socket = null;
  const WEBSOCKET_URL = `wss://${window.location.host}/ws/chat/${chatId}/`;

  // Инициализация WebSocket
  const initWebSocket = () => {
    socket = new WebSocket(WEBSOCKET_URL);

    socket.onopen = () => {
      console.log('WebSocket connected');
    };

    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      renderMessage(message);
      scrollToBottom();
    };

    socket.onclose = () => {
      console.log('WebSocket disconnected');
      // Переподключение через 5 секунд
      setTimeout(initWebSocket, 5000);
    };

    socket.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  };

  // Загрузка истории сообщений
  const loadMessages = async () => {
    try {
      const response = await fetch(`/api/chats/${chatId}/messages/`);
      if (!response.ok) throw new Error('Failed to load messages');
      
      const messages = await response.json();
      messagesContainer.innerHTML = '';
      messages.forEach(message => renderMessage(message));
      scrollToBottom();
    } catch (error) {
      console.error('Error loading messages:', error);
      messagesContainer.innerHTML = '<div class="error">Error loading messages</div>';
    }
  };

  // Отправка сообщения
  const sendMessage = async (content) => {
    if (!content.trim()) return;

    // Блокируем кнопку во время отправки
    sendButton.disabled = true;
    
    try {
      const response = await fetchWithCSRF(`/api/chats/${chatId}/messages/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': db.getCSRFToken()
        },
        body: JSON.stringify({ content })
      });

      if (!response.ok) throw new Error('Message send failed');
      
      messageInput.value = '';
    } catch (error) {
      console.error('Error sending message:', error);
      alert('Error sending message. Please try again.');
    } finally {
      sendButton.disabled = false;
    }
  };

  // Рендеринг сообщения
  const renderMessage = (message) => {
    const messageElement = document.createElement('div');
    messageElement.className = `message ${message.is_own ? 'own-message' : 'other-message'}`;
    messageElement.innerHTML = `
      <div class="message-header">
        <span class="sender">${message.sender_name}</span>
        <span class="timestamp">${new Date(message.timestamp).toLocaleTimeString()}</span>
      </div>
      <div class="message-content">${escapeHTML(message.content)}</div>
    `;
    messagesContainer.appendChild(messageElement);
  };

  // Вспомогательная функция для экранирования HTML
  const escapeHTML = (str) => {
    return str.replace(/[&<>"']/g, 
      match => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      }[match]));
  };

  // Автоскролл к последнему сообщению
  const scrollToBottom = () => {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  };

  // Обработчики событий
  const setupEventListeners = () => {
    chatForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await sendMessage(messageInput.value.trim());
    });

    messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        chatForm.dispatchEvent(new Event('submit'));
      }
    });
  };

  // Инициализация контроллера
  const init = () => {
    if (!chatForm || !messageInput || !messagesContainer) {
      console.error('Missing required DOM elements for chat controller');
      return;
    }

    setupEventListeners();
    loadMessages();
    initWebSocket();
  };

  // Очистка ресурсов
  const destroy = () => {
    if (socket) {
      socket.close();
      socket = null;
    }
    chatForm.removeEventListener('submit', sendMessage);
  };

  // Публичные методы
  return {
    init,
    destroy
  };
}
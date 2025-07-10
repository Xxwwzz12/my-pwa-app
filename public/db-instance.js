import IDBWrapper from './idb.js';

const db = new IDBWrapper('FamilyCache', 2, {
  upgrade: (database) => {
    // Конфигурация хранилищ с указанием ключей
    const storeConfigs = [
      { name: 'families', keyPath: 'id' },
      { name: 'users', keyPath: 'id' },
      { name: 'subscriptions', keyPath: 'id' },
      { name: 'chats', keyPath: 'chatId' },
      { name: 'wishlists', keyPath: 'itemId' }
    ];

    storeConfigs.forEach(config => {
      if (!database.objectStoreNames.contains(config.name)) {
        const store = database.createObjectStore(
          config.name, 
          { keyPath: config.keyPath }
        );
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
    });
  }
});

// Очистка данных старше 30 дней
db.cleanupExpired(30 * 24 * 60 * 60 * 1000); 

// [db-instance.js] Создан экземпляр БД v2 с 5 хранилищами
export default db;
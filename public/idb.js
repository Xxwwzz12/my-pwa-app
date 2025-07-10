export default class IDBWrapper {
  constructor(dbName, version, { upgrade } = {}) {
    this.dbName = dbName;
    this.version = version;
    this.upgrade = upgrade;
    this.db = null;
    this.sizeLimit = 50 * 1024 * 1024; // 50MB
    this.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 дней в миллисекундах
  }

  // Открытие/инициализация базы данных
  async open() {
    if (this.db) return this.db;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
        this.cleanupExpired();
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (this.upgrade) this.upgrade(db);
        
        // Создаем хранилище метаданных, если его нет
        if (!db.objectStoreNames.contains('_metadata')) {
          const metaStore = db.createObjectStore('_metadata', {
            keyPath: 'key'
          });
          metaStore.put({ key: 'totalSize', value: 0 });
        }
      };
    });
  }

  // Очистка устаревших записей
  async cleanupExpired() {
    const now = Date.now();
    const transaction = this.db.transaction(
      Array.from(this.db.objectStoreNames).filter(name => name !== '_metadata'),
      'readwrite'
    );
    
    for (const storeName of transaction.objectStoreNames) {
      if (storeName === '_metadata') continue;
      
      const store = transaction.objectStore(storeName);
      const index = store.index('timestamp');
      const cursor = index.openCursor();
      
      cursor.onsuccess = (event) => {
        const cursor = event.target.result;
        if (!cursor) return;
        
        if (now - cursor.value.timestamp > this.maxAge) {
          cursor.delete();
        }
        cursor.continue();
      };
    }
    
    await new Promise((resolve) => {
      transaction.oncomplete = resolve;
    });
  }

  // Оценка размера записи
  _getObjectSize(obj) {
    const jsonString = JSON.stringify(obj);
    return new TextEncoder().encode(jsonString).length;
  }

  // Проверка и соблюдение лимита хранилища
  async _enforceSizeLimit(storeName, newSize) {
    const transaction = this.db.transaction(['_metadata'], 'readwrite');
    const metaStore = transaction.objectStore('_metadata');
    const sizeReq = metaStore.get('totalSize');
    
    let totalSize = 0;
    sizeReq.onsuccess = () => {
      totalSize = sizeReq.result.value + newSize;
      
      // Если превысили лимит - очищаем самые старые записи
      if (totalSize > this.sizeLimit) {
        const cleanupTransaction = this.db.transaction(
          Array.from(this.db.objectStoreNames).filter(name => name !== '_metadata'),
          'readwrite'
        );
        
        for (const storeName of cleanupTransaction.objectStoreNames) {
          const store = cleanupTransaction.objectStore(storeName);
          const index = store.index('timestamp');
          const cursor = index.openCursor();
          
          cursor.onsuccess = (event) => {
            const cursor = event.target.result;
            if (!cursor || totalSize <= this.sizeLimit) return;
            
            totalSize -= this._getObjectSize(cursor.value);
            cursor.delete();
            cursor.continue();
          };
        }
        
        cleanupTransaction.oncomplete = () => {
          metaStore.put({ key: 'totalSize', value: totalSize });
        };
      } else {
        metaStore.put({ key: 'totalSize', value: totalSize });
      }
    };
    
    await new Promise((resolve) => transaction.oncomplete = resolve);
  }

  // CRUD операции
  async set(storeName, data) {
    if (!this.db) await this.open();
    
    const record = {
      ...data,
      timestamp: Date.now(),
      lastUpdated: Date.now()
    };
    
    const sizeChange = this._getObjectSize(record);
    await this._enforceSizeLimit(storeName, sizeChange);
    
    const transaction = this.db.transaction(storeName, 'readwrite');
    const store = transaction.objectStore(storeName);
    store.put(record);
    
    return new Promise((resolve, reject) => {
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
    });
  }

  async get(storeName, key) {
    if (!this.db) await this.open();
    
    const transaction = this.db.transaction(storeName, 'readonly');
    const store = transaction.objectStore(storeName);
    const request = store.get(key);
    
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async delete(storeName, key) {
    if (!this.db) await this.open();
    
    // Получаем запись для расчета размера
    const record = await this.get(storeName, key);
    if (!record) return;
    
    const transaction = this.db.transaction([storeName, '_metadata'], 'readwrite');
    const store = transaction.objectStore(storeName);
    store.delete(key);
    
    // Обновляем общий размер
    const metaStore = transaction.objectStore('_metadata');
    const sizeReq = metaStore.get('totalSize');
    sizeReq.onsuccess = () => {
      const newSize = sizeReq.result.value - this._getObjectSize(record);
      metaStore.put({ key: 'totalSize', value: newSize });
    };
    
    return new Promise((resolve, reject) => {
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
    });
  }
}
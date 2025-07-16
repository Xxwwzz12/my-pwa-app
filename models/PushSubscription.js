import mongoose from 'mongoose';
import crypto from 'crypto';
import logger from '../utils/logger.js';

// Функция для получения ключа (идентична server.js)
function getKey(secret) {
  return crypto.createHash('sha256')
    .update(secret)
    .digest()
    .subarray(0, 32);
}

// Обновленная функция шифрования (GCM)
function encrypt(text, secret) {
  try {
    const key = getKey(secret);
    const iv = crypto.randomBytes(12); // 12 bytes для GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    
    return `${iv.toString('hex')}:${encrypted}:${authTag}`;
  } catch (error) {
    logger.error(`Encryption process failed: ${error.message}`);
    throw error;
  }
}

// Обновленная функция дешифрования (GCM)
function decrypt(encryptedText, secret) {
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) {
      throw new Error(`Expected 3 parts, got ${parts.length}`);
    }
    
    const key = getKey(secret);
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const authTag = Buffer.from(parts[2], 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    logger.error(`Decryption process failed: ${error.message}`);
    throw error;
  }
}

const pushSubscriptionSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  endpoint: { 
    type: String, 
    required: true,
    unique: true
  },
  keys: {
    type: String,
    required: true
  },
  expirationTime: { 
    type: Number, 
    default: null 
  },
  userAgent: {
    type: String,
    default: ''
  },
  device: {
    type: String,
    enum: ['desktop', 'mobile', 'tablet', 'other'],
    default: 'other'
  }
}, { 
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform: function(doc, ret) {
      delete ret._id;
      delete ret.__v;
      delete ret.keys;
      return ret;
    }
  }
});

// Pre-save хук с диагностикой
pushSubscriptionSchema.pre('save', function(next) {
  logger.info(`Saving push subscription: ${this.endpoint}`);
  
  if (this.isModified('keys') && typeof this.keys === 'object') {
    try {
      // Проверка наличия ENC_KEY
      if (!process.env.ENC_KEY) {
        throw new Error('ENC_KEY is not defined in environment');
      }
      
      // Проверка структуры ключей
      if (!this.keys.auth || !this.keys.p256dh) {
        throw new Error('Invalid keys structure: missing auth or p256dh');
      }
      
      // Диагностика: логирование исходных ключей
      const originalKeys = JSON.stringify(this.keys);
      logger.debug(`Original keys: ${originalKeys}`);
      
      // Шифрование
      const encrypted = encrypt(originalKeys, process.env.ENC_KEY);
      
      // Диагностика: логирование результатов шифрования
      logger.debug(`Encrypted result: ${encrypted.substring(0, 50)}... [${encrypted.length} chars]`);
      
      this.keys = encrypted;
      logger.info(`Keys encrypted for subscription: ${this.endpoint}`);
    } catch (error) {
      logger.error(`Encryption error: ${error.message}`);
      return next(error);
    }
  }
  next();
});

// Метод дешифровки с расширенной диагностикой
pushSubscriptionSchema.methods.decryptKeys = function() {
  try {
    // Диагностика: тип данных в keys
    logger.debug(`Decrypting keys (type: ${typeof this.keys})`);
    
    if (typeof this.keys !== 'string') {
      logger.debug('Returning non-string keys as-is');
      return this.keys;
    }
    
    if (!process.env.ENC_KEY) {
      throw new Error('ENC_KEY is not defined in environment');
    }
    
    // Диагностика: входные данные
    logger.debug(`Encrypted input: ${this.keys.substring(0, 50)}...`);
    
    // Дешифровка
    const decryptedString = decrypt(this.keys, process.env.ENC_KEY);
    
    // Диагностика: расшифрованная строка
    logger.debug(`Decrypted string: ${decryptedString.substring(0, 100)}...`);
    
    // Парсинг JSON
    const keysObject = JSON.parse(decryptedString);
    
    // Диагностика: структура объекта
    logger.debug('Decrypted keys structure:', Object.keys(keysObject));
    
    // Проверка структуры
    if (!keysObject.auth || !keysObject.p256dh) {
      throw new Error('Decrypted keys missing required fields');
    }
    
    return keysObject;
  } catch (error) {
    // Детальное логгирование ошибки
    logger.error(`Decryption failed: ${error.message}`, {
      stack: error.stack,
      input: this.keys ? `${this.keys.substring(0, 50)}...` : 'NULL',
      envKeyPresent: !!process.env.ENC_KEY,
      envKeyLength: process.env.ENC_KEY ? process.env.ENC_KEY.length : 0
    });
    
    throw new Error('Failed to decrypt keys');
  }
};

// Middleware для автоматической дешифровки
pushSubscriptionSchema.post('init', function(doc) {
  try {
    doc.decryptedKeys = doc.decryptKeys();
    logger.debug(`Keys decrypted for subscription: ${doc.endpoint}`);
  } catch (error) {
    logger.error(`Auto-decryption error: ${error.message}`);
    doc.decryptionError = error;
  }
});

// Индексы, виртуальные поля и статические методы остаются без изменений
pushSubscriptionSchema.index({ userId: 1, endpoint: 1 }, { unique: true });
pushSubscriptionSchema.index({ expirationTime: 1 }, { expireAfterSeconds: 0 });

pushSubscriptionSchema.virtual('age').get(function() {
  if (!this.createdAt) return 0;
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

pushSubscriptionSchema.statics.getDeviceStats = async function(userId) {
  // ... существующая реализация ...
};

const PushSubscription = mongoose.model('PushSubscription', pushSubscriptionSchema);

export default PushSubscription;
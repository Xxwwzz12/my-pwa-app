import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import fs from 'fs';
import webpush from 'web-push';
import dotenv from 'dotenv';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import winston from 'winston';
import 'winston-daily-rotate-file';
import crypto from 'crypto';
import { body, validationResult } from 'express-validator';

// Инициализация переменных окружения
dotenv.config();

// Получение текущего пути файла
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Импорт моделей
import User from './models/User.js';
import PushSubscription from './models/PushSubscription.js';

// Конфигурация логгера
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      level: 'error',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxFiles: '30d'
    }),
    new winston.transports.DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxFiles: '30d'
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ],
  exceptionHandlers: [
    new winston.transports.DailyRotateFile({
      filename: 'logs/exceptions-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxFiles: '30d'
    })
  ]
});

// Обработчик критических ошибок
process.on('uncaughtException', (err) => {
  logger.error(`Critical Uncaught Exception: ${err.message}`, { stack: err.stack });
  process.exit(1);
});

const FRONTEND_URL = process.env.FRONTEND_URL;

const app = express();

// Проверка обязательных переменных окружения
const REQUIRED_ENV = [
  'MONGO_URI', 
  'SESSION_SECRET',
  'VAPID_PUBLIC_KEY',
  'VAPID_PRIVATE_KEY',
  'CSRF_SECRET',
  'ENC_KEY'
];

const missing = REQUIRED_ENV.filter(key => !process.env[key]);
if (missing.length > 0) {
  logger.error(`FATAL: Missing required env variables: ${missing.join(', ')}`);
  process.exit(1);
}

// Middleware для генерации nonce для CSP
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

// Настройка Helmet с CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'", 
        (req, res) => `'nonce-${res.locals.nonce}'`,
        "https://apis.google.com"
      ],
      styleSrc: [
        "'self'", 
        (req, res) => `'nonce-${res.locals.nonce}'`,
        "https://fonts.googleapis.com"
      ],
      imgSrc: ["'self'", "data:", "https://lh3.googleusercontent.com"],
      connectSrc: ["'self'", "https://accounts.google.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'", "https://accounts.google.com"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'same-origin' }
}));

// Разрешение CORS для всех в development
if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
    next();
  });
  logger.warn('⚠️ Разрешение CORS для всех в development режиме');
}

// Добавление HSTS в PRODUCTION
if (process.env.NODE_ENV === 'production') {
  app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }));
  
  // Force HTTPS
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// Middleware сжатия
app.use(compression());

// Multer Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    allowed.includes(file.mimetype) ? cb(null, true) : cb(new Error('Only JPG, PNG and WEBP formats allowed'));
  }
});

// Подключение к MongoDB
async function connectToMongoDB() {
  try {
    logger.info('Подключение к MongoDB...');
    
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      maxPoolSize: 10,
      heartbeatFrequencyMS: 30000,
      retryWrites: true,
      w: 'majority'
    });
    
    logger.info('MongoDB подключен успешно');
    return true;
  } catch (err) {
    logger.error(`Ошибка подключения к MongoDB: ${err.message}`, { stack: err.stack });
    return false;
  }
}

// Настройка VAPID
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    'mailto:contact@familyspace.app',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
  logger.info('VAPID ключи настроены');
}

// Глобальный лимит запросов
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.set('trust proxy', 1);

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1y',
  setHeaders: (res, filePath) => filePath.endsWith('.html') && res.setHeader('Cache-Control', 'no-store')
}));

// Защита загрузок
app.use('/uploads', (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.status(403).send('Доступ запрещен');
}, express.static(path.join(__dirname, 'uploads')));

// Cookie parser
app.use(cookieParser());

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Слишком много запросов, попробуйте позже',
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Слишком много попыток аутентификации',
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api', apiLimiter);
app.use('/auth', authLimiter);

// CORS
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = [
    FRONTEND_URL,
    'https://my-pwa-app-w519.onrender.com',
    'http://localhost:3000',
    'http://localhost:8080'
  ];
  
  if (allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin,Content-Type,Accept,Authorization,X-CSRF-Token');
    return res.sendStatus(204);
  }
  next();
});

// Защита от доступа к скрытым файлам
app.use((req, res, next) => {
  if (req.path.split('/').some(part => part.startsWith('.'))) {
    return res.status(403).send('Forbidden');
  }
  next();
});

// Session Configuration
const sessionConfig = {
  name: process.env.SESSION_NAME || 'session',
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGO_URI, 
    collectionName: 'sessions', 
    ttl: 14 * 24 * 60 * 60,
    autoRemove: 'interval',
    autoRemoveInterval: 60
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 14 * 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: process.env.NODE_ENV === 'production' ? process.env.SESSION_DOMAIN : undefined
  }
};

if (process.env.NODE_ENV === 'production') {
  sessionConfig.name = `__Secure-${sessionConfig.name}`;
  sessionConfig.cookie.sameSite = 'none';
  sessionConfig.cookie.secure = true;
  
  if (process.env.SESSION_DOMAIN) {
    sessionConfig.cookie.domain = process.env.SESSION_DOMAIN;
  }
}

app.use(session(sessionConfig));

// Passport Initialization
app.use(passport.initialize());
app.use(passport.session());

// =================================================
// ОБНОВЛЕННАЯ РЕАЛИЗАЦИЯ CSRF ЗАЩИТЫ (СЕССИОННАЯ)
// =================================================

// Middleware проверки CSRF
const csrfProtection = (req, res, next) => {
  if (['GET', 'OPTIONS', 'HEAD'].includes(req.method)) {
    logger.debug(`[CSRF] Пропуск проверки для метода: ${req.method}`);
    return next();
  }
  
  const clientToken = req.headers['csrf-token'];
  const serverToken = req.session.csrfToken;
  
  logger.debug(`[CSRF] Токен клиента: ${clientToken}`);
  logger.debug(`[CSRF] Токен сервера: ${serverToken}`);
  
  if (!clientToken || clientToken !== serverToken) {
    logger.warn(`Несоответствие CSRF токена! Клиент: ${clientToken}, Сервер: ${serverToken}`);
    return res.status(419).json({ error: 'CSRF token mismatch' });
  }
  
  logger.debug('[CSRF] Токен верифицирован');
  next();
};

// Эндпоинт для получения CSRF-токена
app.get('/api/csrf-token', (req, res) => {
  try {
    const token = crypto.randomBytes(32).toString('hex');
    req.session.csrfToken = token;
    
    logger.debug(`[CSRF] Сгенерирован токен: ${token}`);
    logger.debug(`[CSRF] ID сессии: ${req.sessionID}`);
    
    // Устанавливаем cookie для совместимости с фронтендом
    res.cookie('XSRF-TOKEN', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/'
    });
    
    res.json({ token });
  } catch (error) {
    logger.error('Ошибка генерации CSRF токена:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Применяем CSRF защиту ко всем маршрутам, кроме статических файлов и /api/csrf-token
app.use((req, res, next) => {
  if (req.path === '/api/csrf-token') return next();
  if (req.path.startsWith('/public/')) return next();
  if (req.path.startsWith('/uploads/')) return next();
  csrfProtection(req, res, next);
});

// =================================================
// ШИФРОВАНИЕ ДЛЯ PUSH-КЛЮЧЕЙ
// =================================================
function getKey(secret) {
  return crypto.createHash('sha256')
    .update(secret)
    .digest()
    .subarray(0, 32);
}

function encrypt(text, secretKey) {
  const key = getKey(secretKey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  
  return `${iv.toString('hex')}:${encrypted}:${authTag}`;
}

function decrypt(encryptedText, secretKey) {
  const parts = encryptedText.split(':');
  if (parts.length !== 3) {
    throw new Error(`Invalid encrypted text format. Expected 3 parts but got ${parts.length}`);
  }
  
  const key = getKey(secretKey);
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const authTag = Buffer.from(parts[2], 'hex');
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL || `${process.env.BASE_URL}/auth/google/callback`,
  passReqToCallback: true,
  proxy: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (user) return done(null, user);
    
    user = new User({ 
      googleId: profile.id, 
      email: profile.emails[0].value, 
      firstName: profile.name.givenName, 
      lastName: profile.name.familyName, 
      gender: null, 
      age: null, 
      role: 'member' 
    });
    
    await user.save();
    logger.info(`Новый пользователь: ${user.email}`);
    done(null, user);
  } catch (err) {
    logger.error(`Google OAuth ошибка: ${err.message}`, { stack: err.stack });
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user || null);
  } catch (err) {
    logger.error(`Ошибка десериализации: ${err.message}`, { stack: err.stack });
    done(err);
  }
});

// Auth Routes
app.get('/auth/google', authLimiter, passport.authenticate('google', { 
  scope: ['profile','email'], 
  prompt: 'select_account' 
}));

app.get('/auth/google/callback', 
  authLimiter,
  passport.authenticate('google', { failureRedirect: '/?auth_error=1' }), 
  (req, res) => res.redirect(FRONTEND_URL + '/family.html')
);

app.get('/logout', (req, res) => {
  PushSubscription.deleteMany({ userId: req.user.id }).exec().then(() => {
    logger.info(`Подписки удалены: ${req.user.id}`);
  }).catch(err => {
    logger.error(`Ошибка удаления подписок: ${err.message}`);
  });
  
  req.logout(err => {
    if (err) logger.error(`Ошибка выхода: ${err.message}`, { stack: err.stack });
  });
  
  req.session.destroy(() => { 
    res.clearCookie(sessionConfig.name); 
    res.redirect('/'); 
  });
});

// Middleware проверки аутентификации
const checkAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  logger.warn(`Неавторизованный доступ: ${req.originalUrl}`);
  res.redirect('/');
};

// User API
app.get('/api/user', checkAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      logger.warn(`Пользователь не найден: ${req.user.id}`);
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    res.json({ 
      id: user._id, 
      email: user.email, 
      firstName: user.firstName, 
      lastName: user.lastName, 
      gender: user.gender, 
      age: user.age, 
      role: user.role, 
      avatar: user.avatar 
    });
  } catch (err) {
    logger.error(`Ошибка API пользователя: ${err.message}`, { stack: err.stack });
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Обработчик подписки на push-уведомления
app.post(
  '/api/push-subscribe',
  checkAuth,
  [
    body('endpoint').isURL().withMessage('Некорректный endpoint URL'),
    body('keys.auth').isString().withMessage('Ключ auth должен быть строкой'),
    body('keys.p256dh').isString().withMessage('Ключ p256dh должен быть строкой')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Ошибка валидации подписки', {
        errors: errors.array()
      });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { endpoint, keys } = req.body;
      const userId = req.user.id;
      
      logger.info(`Сохранение подписки для пользователя: ${userId}`);
      
      // Шифруем ключи перед сохранением
      const keysString = JSON.stringify(keys);
      const encryptedKeys = encrypt(keysString, process.env.ENC_KEY);
      
      const subscription = new PushSubscription({
        endpoint,
        keys: encryptedKeys,
        userId: userId
      });
      
      const savedSub = await subscription.save();
      logger.info(`Подписка сохранена: ${savedSub._id}`);
      
      // Проверяем дешифровку сразу после сохранения
      try {
        const decryptedKeys = decrypt(encryptedKeys, process.env.ENC_KEY);
        logger.debug('Успешная дешифровка ключей после сохранения');
        logger.debug(`Дешифрованные ключи: ${decryptedKeys}`);
      } catch (decryptError) {
        logger.error('Ошибка дешифровки после сохранения', {
          error: decryptError.message,
          stack: decryptError.stack
        });
      }
      
      res.status(201).json({ 
        success: true, 
        message: 'Подписка успешно сохранена',
        subscriptionId: savedSub._id
      });
    } catch (error) {
      if (error.name === 'MongoServerError' && error.code === 11000) {
        logger.warn('Дубликат подписки', { 
          endpoint: req.body.endpoint
        });
        return res.status(409).json({ error: 'Подписка уже существует' });
      }
      
      logger.error(`Ошибка подписки: ${error.message}`, { 
        stack: error.stack,
        body: req.body
      });
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  }
);

// Эндпоинт для уведомлений
app.get('/api/notifications', (req, res) => {
  res.json({ 
    status: 'success',
    data: [
      {id: 1, text: "Доступно обновление системы"},
      {id: 2, text: "Новое сообщение от Алексея"}
    ]
  });
});

// Защищенный эндпоинт загрузки аватара
app.post(
  '/api/upload-avatar',
  upload.single('avatar'),
  checkAuth,
  [
    body('userId').isMongoId().withMessage('Некорректный ID пользователя'),
    body('avatarType').isIn(['user', 'family']).withMessage('Некорректный тип аватара')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'Файл не загружен' });
      }
      
      const user = await User.findById(req.user.id);
      if (user.avatar) {
        fs.unlink(path.join(__dirname, 'uploads', user.avatar), err => {
          if (err) logger.error(`Ошибка удаления аватара: ${err.message}`);
        });
      }
      
      await User.findByIdAndUpdate(req.user.id, { avatar: req.file.filename });
      logger.info(`Аватар обновлен: ${user.email}`);
      res.json({ success: true, avatarUrl: `/uploads/${req.file.filename}` });
    } catch (err) {
      logger.error(`Ошибка загрузки аватара: ${err.message}`);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  }
);

// Static & SPA routes
const staticRoutes = [
  '/family.html',
  '/profile.html',
  '/registration.html',
  '/test-notifications.html'
];

staticRoutes.forEach(route => {
  app.get(route, checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', path.basename(route)));
  });
});

app.get('/offline', (req, res) => res.sendFile(path.join(__dirname, 'public', 'offline.html')));
app.get('/', (req, res) => req.query.connection_test ? res.sendStatus(204) : res.sendFile(path.join(__dirname, 'public', 'index.html')));

// API fallback
app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found' }));

// Обработка 404
app.get(/(.*)/, (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  
  const filePath = path.join(__dirname, 'public', req.path);
  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }
  
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Error Handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'Ошибка загрузки файла: ' + err.message });
  }
  
  if (err.message === 'Invalid JSON') {
    return res.status(400).json({ error: 'Некорректный JSON' });
  }
  
  logger.error(`Ошибка сервера: ${err.message}`, { 
    stack: err.stack,
    url: req.originalUrl,
    method: req.method
  });
  
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// Start Server
let server;

async function startServer() {
  const ok = await connectToMongoDB();
  if (!ok) process.exit(1);
  
  const PORT = process.env.PORT || 3000;
  server = app.listen(PORT, () => {
    logger.info(`Сервер запущен на порту ${PORT} в режиме ${process.env.NODE_ENV}`);
    logger.info('Обновленная CSRF защита активирована (сессионная реализация)');
    logger.info(`Frontend URL: ${FRONTEND_URL}`);
    
    // Тест шифрования в development
    if (process.env.NODE_ENV === 'development') {
      console.log('\n=== Testing encryption ===');
      const testText = 'FamilySpaceSecret123';
      const encrypted = encrypt(testText, process.env.ENC_KEY);
      console.log('Encrypted:', encrypted);
      
      const decrypted = decrypt(encrypted, process.env.ENC_KEY);
      console.log('Decrypted:', decrypted);
      console.log('Test', decrypted === testText ? 'PASSED' : 'FAILED');
      console.log('=======================\n');
    }
  });
}

process.on('SIGTERM', () => {
  logger.info('SIGTERM получен. Завершение работы');
  server.close(() => {
    mongoose.connection.close(false, () => {
      logger.info('Подключение к MongoDB закрыто');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT получен. Завершение работы');
  server.close(() => {
    mongoose.connection.close(false, () => {
      logger.info('Подключение к MongoDB закрыто');
      process.exit(0);
    });
  });
});

startServer();
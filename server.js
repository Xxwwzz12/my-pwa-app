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
import expressValidator from 'express-validator';
import winston from 'winston';
import 'winston-daily-rotate-file';
import crypto from 'crypto';

const { body, validationResult } = expressValidator;

// Получение текущего пути файла
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Конфигурация логгера
const logger = winston.createLogger({
  level: 'info',
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
      format: winston.format.simple()
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

dotenv.config();
const FRONTEND_URL = process.env.FRONTEND_URL;

const app = express();

// Force HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
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
      frameSrc: ["https://accounts.google.com"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false
}));

// Добавление HSTS в production
if (process.env.NODE_ENV === 'production') {
  app.use(helmet.hsts({
    maxAge: 31536000, // 1 год
    includeSubDomains: true,
    preload: true
  }));
  logger.info('HSTS middleware enabled');
}

// Middleware сжатия
app.use(compression());

// Multer Configuration с валидацией типов
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

// Подключение к MongoDB с улучшенной обработкой ошибок
async function connectToMongoDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: parseInt(process.env.DB_TIMEOUT_MS || '10000'),
      maxPoolSize: parseInt(process.env.DB_POOL_SIZE || '10'),
      heartbeatFrequencyMS: 30000,
      retryWrites: true,
      w: 'majority'
    });
    logger.info('MongoDB connected successfully');
    mongoose.connection.on('error', err => 
      logger.error(`MongoDB connection error: ${err.message}`, { stack: err.stack }));
    mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'));
    return true;
  } catch (err) {
    logger.error(`MongoDB initial connection error: ${err.message}`, { stack: err.stack });
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
  logger.info('VAPID keys configured successfully');
} else {
  logger.warn('VAPID keys not configured! Push notifications disabled.');
}

// Глобальный лимит запросов и body-parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.set('trust proxy', 1);

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1y',
  setHeaders: (res, filePath) => filePath.endsWith('.html') && res.setHeader('Cache-Control', 'no-store')
}));
app.use('/images', express.static(path.join(__dirname, 'public', 'images')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Cookie parser
app.use(cookieParser());

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many authentication attempts, please try again later',
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
    res.setHeader('Access-Control-Allow-Headers', 'Origin,Content-Type,Accept,Authorization');
    return res.sendStatus(204);
  }
  next();
});

// Session Configuration
app.use(session({
  name: process.env.SESSION_NAME,
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGO_URI, 
    collectionName: 'sessions', 
    ttl: 14 * 24 * 60 * 60,
    autoRemove: 'interval',
    autoRemoveInterval: 60 // minutes
  }),
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 14 * 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: process.env.SESSION_DOMAIN
  }
}));

// Passport Initialization
app.use(passport.initialize());
app.use(passport.session());

// CSRF Protection
let doubleCsrfProtection = (req, res, next) => next(); // Заглушка на время инициализации

import('csrf-csrf').then(({ doubleCsrf }) => {
  const { generateToken, doubleCsrfProtection: csrfProtection } = doubleCsrf({
    getSecret: () => process.env.SESSION_SECRET,
    cookieName: 'x-csrf-token',
    cookieOptions: { 
      httpOnly: true, 
      sameSite: 'lax', 
      secure: process.env.NODE_ENV === 'production', 
      domain: process.env.SESSION_DOMAIN 
    },
    size: 64,
    ignoredMethods: ['GET','HEAD','OPTIONS']
  });
  
  doubleCsrfProtection = csrfProtection;
  
  app.use((req, res, next) => {
    const token = generateToken(res);
    res.cookie('x-csrf-token', token, { 
      httpOnly: true, 
      sameSite: 'lax', 
      secure: process.env.NODE_ENV === 'production', 
      domain: process.env.SESSION_DOMAIN,
      maxAge: 14 * 24 * 60 * 60 * 1000 
    });
    next();
  });
  
  logger.info('CSRF protection initialized');
}).catch(err => {
  logger.error(`CSRF initialization error: ${err.message}`, { stack: err.stack });
});

// Импорт модели пользователя
import User from './models/User.js';

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
    logger.info(`New user created: ${user.email}`);
    done(null, user);
  } catch (err) {
    logger.error(`Google OAuth error: ${err.message}`, { stack: err.stack });
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user || null);
  } catch (err) {
    logger.error(`Deserialize user error: ${err.message}`, { stack: err.stack });
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
  req.logout(err => {
    if (err) logger.error(`Logout error: ${err.message}`, { stack: err.stack });
  });
  
  req.session.destroy(() => { 
    res.clearCookie(process.env.SESSION_NAME); 
    res.redirect('/'); 
  });
});

// Middleware to check auth
const checkAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  logger.warn(`Unauthorized access attempt to ${req.originalUrl}`);
  res.redirect('/');
};

// User API
app.get('/api/user', checkAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      logger.warn(`User not found: ${req.user.id}`);
      return res.status(404).json({ error: 'User not found' });
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
    logger.error(`User API error: ${err.message}`, { stack: err.stack });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post(
  '/api/upload-avatar',
  (req, res, next) => doubleCsrfProtection(req, res, next),
  [
    body('userId').isMongoId().withMessage('Invalid user ID'),
    body('avatarType').isIn(['user', 'family']).withMessage('Invalid avatar type'),
    body('avatar').custom((value, { req }) => {
      if (!req.file) throw new Error('Avatar file is required');
      return true;
    })
  ],
  upload.single('avatar'),
  checkAuth,
  async (req, res) => {
    // Валидация данных
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn(`Avatar upload validation failed: ${JSON.stringify(errors.array())}`);
      return res.status(400).json({ errors: errors.array() });
    }
    
    try {
      if (!req.file) {
        logger.warn('No file uploaded for avatar');
        return res.status(400).json({ error: 'No file uploaded' });
      }
      
      const user = await User.findById(req.user.id);
      if (user.avatar) {
        fs.unlink(path.join(__dirname, 'uploads', user.avatar), err => {
          if (err) logger.error(`Error deleting old avatar: ${err.message}`, { stack: err.stack });
        });
      }
      
      await User.findByIdAndUpdate(req.user.id, { avatar: req.file.filename });
      logger.info(`Avatar updated for user: ${user.email}`);
      res.json({ success: true, avatarUrl: `/uploads/${req.file.filename}` });
    } catch (err) {
      logger.error(`Avatar upload error: ${err.message}`, { stack: err.stack });
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// Push Notification API
app.post(
  '/send-push',
  authLimiter,
  [
    body('subscription').isObject().withMessage('Invalid subscription format'),
    body('payload').isObject().withMessage('Invalid payload format'),
    body('payload.title').isString().notEmpty().withMessage('Title is required'),
    body('payload.body').isString().optional(),
    body('payload.icon').isString().optional(),
    body('payload.url').isString().optional()
  ],
  async (req, res) => {
    // Валидация данных
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('[PUSH] Validation failed', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { subscription, payload } = req.body;
    
    try {
      await webpush.sendNotification(
        subscription, 
        JSON.stringify(payload)
      );
      logger.info('[PUSH] Notification sent successfully');
      res.status(200).json({ status: 'OK' });
    } catch (err) {
      logger.error(`[PUSH] Error: ${err.message}`, { 
        stack: err.stack,
        subscription: subscription.endpoint 
      });
      res.status(500).json({ error: 'Failed to send push notification' });
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

// SPA fallback
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error Handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN' || err.status === 403) {
    logger.warn(`Invalid CSRF token: ${err.message}`);
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  if (err instanceof multer.MulterError) {
    logger.warn(`File upload error: ${err.message}`);
    return res.status(400).json({ error: 'File upload error: ' + err.message });
  }
  
  logger.error(`Server Error: ${err.message}`, { stack: err.stack });
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start Server
let server;

async function startServer() {
  const ok = await connectToMongoDB();
  if (!ok) process.exit(1);
  
  const PORT = process.env.PORT || 3000;
  server = app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
    logger.info('Security features:');
    logger.info(`- Helmet CSP: enabled`);
    logger.info(`- CSRF Protection: enabled (x-csrf-token)`);
    logger.info(`- HTTP-Only cookies: enabled`);
    logger.info(`- Rate Limiter: API=100/15min, Auth=10/15min`);
    logger.info('Optimizations:');
    logger.info(`- Gzip compression: enabled`);
    logger.info(`- Static caching: 1 year (except HTML)`);
    logger.info(`- File upload limit: 5MB`);
    logger.info(`- Request body limit: 10MB`);
    logger.info('\nEnvironment:');
    logger.info(`- FRONTEND_URL: ${FRONTEND_URL}`);
    logger.info(`- MongoDB: ${mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'}`);
    logger.info(`- OAuth Callback: ${process.env.CALLBACK_URL || `${process.env.BASE_URL}/auth/google/callback`}`);
    if (process.env.NODE_ENV === 'production') {
      logger.info(`- HSTS: enabled with preload`);
    }
  });
}

// Грациозное завершение
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully');
  server.close(() => {
    mongoose.connection.close(false, () => {
      logger.info('MongoDB connection closed');
      process.exit(0);
    });
  });
});

startServer();
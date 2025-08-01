const express = require('express');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const webpush = require('web-push');
const dotenv = require('dotenv');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');

// Инициализация переменных окружения
dotenv.config();

// Получение текущего пути
const currentDir = path.resolve();

// Импорт моделей
const User = require('./models/User');
const PushSubscription = require('./models/PushSubscription');

// Конфигурация логгера
const logger = {
  info: (msg) => console.log(`[INFO] ${msg}`),
  error: (msg) => console.error(`[ERROR] ${msg}`)
};

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
  "'unsafe-inline'", // Разрешаем inline-скрипты
  "https://apis.google.com"
],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", // Разрешаем inline-стили
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

// Базовые middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(compression());

// Подключение к MongoDB
async function connectToMongoDB() {
  try {
    logger.info('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGO_URI);
    logger.info('MongoDB connected successfully');
    return true;
  } catch (err) {
    logger.error(`MongoDB connection error: ${err.message}`);
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
  logger.info('VAPID keys configured');
}

// Static files
app.use(express.static(path.join(currentDir, 'public')));

// Обработчик для manifest.json с правильным заголовком
app.get('/manifest.json', (req, res) => {
  res.setHeader('Content-Type', 'application/manifest+json');
  res.sendFile(path.join(currentDir, 'public', 'manifest.json'));
});

// Session Configuration
const sessionConfig = {
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 14 * 24 * 60 * 60 * 1000, // 14 дней
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
};

app.use(session(sessionConfig));

// Passport Initialization
app.use(passport.initialize());
app.use(passport.session());

// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL || '/auth/google/callback',
  proxy: true
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    
    if (!user) {
      user = new User({ 
        googleId: profile.id, 
        email: profile.emails[0].value,
        firstName: profile.name?.givenName || '',
        lastName: profile.name?.familyName || '',
        role: 'member'
      });
      await user.save();
      logger.info(`New user created: ${user.email}`);
    }
    
    done(null, user);
  } catch (err) {
    logger.error(`Google OAuth error: ${err.message}`);
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    logger.error(`Deserialization error: ${err.message}`);
    done(err);
  }
});

// Middleware проверки аутентификации
const checkAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/');
};

// Регистрация маршрутов
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/?auth_error=1' }), 
  (req, res) => res.redirect(FRONTEND_URL || '/family.html')
);

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) logger.error(`Logout error: ${err.message}`);
    res.redirect('/');
  });
});

app.get('/api/user', checkAuth, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    firstName: req.user.firstName,
    lastName: req.user.lastName,
    role: req.user.role
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(currentDir, 'public', 'index.html'));
});

// Обработка 404
app.use((req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  res.status(404).sendFile(path.join(currentDir, 'public', '404.html'));
});

// Обработчик ошибок
app.use((err, req, res, next) => {
  logger.error(`Server error: ${err.message}`);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Запуск сервера
async function startServer() {
  const connected = await connectToMongoDB();
  if (!connected) process.exit(1);
  
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════╗
║   Server successfully started on port ${PORT}     ║
╚══════════════════════════════════════════════════╝
`);
    console.log('Registered routes:');
    console.log('GET /auth/google');
    console.log('GET /auth/google/callback');
    console.log('GET /logout');
    console.log('GET /api/user');
    console.log('GET /');
    console.log('GET /manifest.json');
    console.log('------------------------------------');
  });
}

startServer();
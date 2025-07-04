import express from 'express';
import path from 'path';
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
dotenv.config();

// Импорт модели пользователя
import User from './models/User.js';
import PushSubscription from './models/PushSubscription.js';

const __dirname = path.resolve();
const app = express();

// ========== Подключение к MongoDB ==========
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// ========== Конфигурация Google OAuth ==========
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://my-pwa-app-w519.onrender.com/auth/google/callback';

// ========== Настройка VAPID для push-уведомлений ==========
if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) {
  console.error('VAPID ключи не установлены! Push-уведомления работать не будут.');
} else {
  webpush.setVapidDetails(
    'mailto:contact@familyspace.app',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
  console.log('VAPID ключи успешно настроены');
}

// ========== Настройка Multer для загрузки аватаров ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Неподдерживаемый тип файла'), false);
    }
  }
});

// ========== Middleware ==========
app.set('trust proxy', 1);

// Обновленная обработка статических файлов
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'public', 'images')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ========== Улучшенный CORS Middleware ==========
const allowedOrigins = [
  'https://my-pwa-app-w519.onrender.com',
  'http://localhost:3000',
  'http://localhost:8080'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Разрешаем preflight запросы
  if (req.method === 'OPTIONS') {
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    return res.sendStatus(200);
  }

  // Проверяем и разрешаем только доверенные источники
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});

// ========== Конфигурация сессий с MongoDB Store ==========
app.use(session({
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60 // 14 дней в секундах
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // true в production
    maxAge: 14 * 24 * 60 * 60 * 1000, // 14 дней
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' // none для кросс-доменных запросов
  }
}));

// Инициализация Passport
app.use(passport.initialize());
app.use(passport.session());

// ========== Passport стратегия Google ==========
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL,
    passReqToCallback: true,
    proxy: true
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      // Поиск существующего пользователя
      let user = await User.findOne({ googleId: profile.id });
      
      if (user) {
        return done(null, user);
      }
      
      // Создание нового пользователя
      user = new User({
        googleId: profile.id,
        email: profile.emails?.[0]?.value || '',
        firstName: profile.name?.givenName || '',
        lastName: profile.name?.familyName || '',
        gender: 'other',
        age: 25,
        role: 'parent'
      });
      
      await user.save();
      return done(null, user);
    } catch (error) {
      console.error('GoogleStrategy error:', error);
      return done(error);
    }
  }
));

// Сериализация пользователя
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Десериализация пользователя
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// ========== Middleware для проверки регистрации ==========
function checkRegistration(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}

// ========== Маршруты аутентификации ==========
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?auth_error=1' }),
  (req, res) => {
    res.redirect('/family.html');
  }
);

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) console.error('Logout error:', err);
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  });
});

// ========== API для работы с пользователем ==========

// Получение данных пользователя
app.get('/api/user', async (req, res) => {
  try {
    // Проверка аутентификации
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: 'Не авторизован' });
    }

    const user = await User.findById(req.user.id).select('-__v');
    
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    // Формирование ответа
    res.json({
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      gender: user.gender,
      age: user.age,
      role: user.role,
      avatar: user.avatar || null,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Ошибка получения данных пользователя:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Загрузка аватара
app.post('/api/upload-avatar', 
  passport.authenticate('session'), 
  upload.single('avatar'), 
  async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Не авторизован' });
      }
      
      if (!req.file) {
        return res.status(400).json({ error: 'Файл не загружен' });
      }

      // Обновление аватара пользователя в БД
      const user = await User.findByIdAndUpdate(req.user.id, {
        avatar: req.file.filename
      }, { new: true });

      res.json({ 
        success: true,
        fileName: req.file.filename,
        avatarUrl: `/uploads/${req.file.filename}`
      });
    } catch (error) {
      console.error('Ошибка загрузки аватара:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  }
);

// Сохранение профиля
app.post('/api/save-profile', 
  express.json(),
  passport.authenticate('session'),
  async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Не авторизован' });
      }
      
      const { firstName, lastName, gender, age, role, avatarUrl } = req.body;
      
      // Базовая валидация
      if (!firstName || !lastName || !gender || !age || !role) {
        return res.status(400).json({ error: 'Заполните все обязательные поля' });
      }

      // Обновление данных пользователя
      const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        {
          firstName,
          lastName,
          gender,
          age: parseInt(age),
          role,
          avatar: avatarUrl || null
        },
        { new: true }
      );

      res.json({
        success: true,
        user: updatedUser
      });
    } catch (error) {
      console.error('Ошибка сохранения профиля:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  }
);

// ========== API для управления подписками ==========
app.get('/api/subscriptions', async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: 'Не авторизован' });
    }
    
    const subscriptions = await PushSubscription.find({ userId: req.user.id });
    res.json(subscriptions);
  } catch (error) {
    console.error('Ошибка получения подписок:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.delete('/api/subscriptions/:id', async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: 'Не авторизован' });
    }
    
    const subscription = await PushSubscription.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.id
    });
    
    if (!subscription) {
      return res.status(404).json({ error: 'Подписка не найдена' });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Ошибка удаления подписки:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ========== API для тестирования уведомлений ==========
app.post('/api/test-notification', async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: 'Не авторизован' });
    }
    
    // Получаем подписки пользователя
    const subscriptions = await PushSubscription.find({ userId: req.user.id });
    if (subscriptions.length === 0) {
      return res.status(404).json({ error: 'Активные подписки не найдены' });
    }
    
    // Отправляем уведомление на каждую подписку
    const results = [];
    
    for (const sub of subscriptions) {
      try {
        const pushSubscription = {
          endpoint: sub.endpoint,
          keys: {
            p256dh: sub.keys.p256dh,
            auth: sub.keys.auth
          }
        };
        
        const payload = JSON.stringify({
          title: "Тестовое уведомление",
          body: `Проверка работы системы уведомлений (${new Date().toLocaleTimeString()})`,
          url: "/family.html"
        });
        
        await webpush.sendNotification(pushSubscription, payload);
        results.push({ id: sub._id, status: 'success' });
      } catch (error) {
        // Если подписка недействительна - удаляем
        if (error.statusCode === 410) {
          await PushSubscription.findByIdAndDelete(sub._id);
          results.push({ id: sub._id, status: 'expired', message: 'Подписка устарела и удалена' });
        } else {
          results.push({ id: sub._id, status: 'error', message: error.message });
        }
      }
    }
    
    res.json({
      success: true,
      sentCount: results.filter(r => r.status === 'success').length,
      total: subscriptions.length,
      results
    });
  } catch (error) {
    console.error('Ошибка отправки тестового уведомления:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ========== Защищенные маршруты ==========
app.get('/family.html', checkRegistration, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'family.html'));
});

app.get('/profile.html', checkRegistration, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/registration.html', checkRegistration, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'registration.html'));
});

app.get('/test-notifications.html', checkRegistration, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'test-notifications.html'));
});

// ========== Подключение API уведомлений ==========
import notificationsRouter from './api/notifications.js';
app.use('/api/notifications', notificationsRouter);

// ========== API для проверки обновлений ==========
app.get('/api/check-update', (req, res) => {
  try {
    import('./api/check-update.js')
      .then(module => module.default(req, res))
      .catch(error => {
        console.error('Ошибка загрузки API модуля:', error);
        res.status(500).json({ error: "Internal server error" });
      });
  } catch (error) {
    console.error('Ошибка загрузки API модуля:', error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========== API для получения VAPID ключа ==========
app.get('/api/vapid-public-key', (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY) {
    return res.status(503).json({ 
      error: 'VAPID ключи не настроены на сервере',
      code: 'VAPID_NOT_CONFIGURED'
    });
  }
  
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

// ========== Базовые маршруты ==========
app.get('/offline', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'offline.html'));
});

app.get('/', (req, res) => {
  if (req.query.connection_test) {
    res.sendStatus(204);
  } else {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Обработчик ошибок Multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'Ошибка загрузки файла: ' + err.message });
  } else if (err) {
    console.error('Server error:', err);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
  next();
});

// Обработчик ошибок API
app.use((err, req, res, next) => {
  console.error('Ошибка API:', err.stack);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      error: 'Ошибка валидации', 
      details: err.errors 
    });
  }
  
  res.status(500).json({ 
    error: 'Внутренняя ошибка сервера',
    code: 'INTERNAL_SERVER_ERROR',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ========== Запуск сервера ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
  console.log('Конфигурация OAuth:');
  console.log(`- Client ID: ${GOOGLE_CLIENT_ID ? 'установлен' : 'ОШИБКА! Проверьте .env'}`);
  console.log(`- Callback URL: ${CALLBACK_URL}`);
  console.log(`- MongoDB URI: ${process.env.MONGO_URI ? 'установлен' : 'ОШИБКА! Проверьте .env'}`);
  console.log('Хранилище сессий: MongoDB');
  
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    console.error('ВНИМАНИЕ: Google OAuth credentials не установлены!');
  }
  
  if (!process.env.MONGO_URI) {
    console.error('ВНИМАНИЕ: MongoDB URI не установлен!');
  }
  
  console.log('Push-уведомления:', 
    process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY ? 
    'настроены' : 'ОШИБКА! Проверьте VAPID ключи в .env');
    
  console.log('Тестовые страницы:');
  console.log(`- Уведомления: http://localhost:${PORT}/test-notifications.html`);
});

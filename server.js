const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config();

const app = express();

// ========== Конфигурация Google OAuth ==========
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://my-pwa-app-w519.onrender.com/auth/google/callback';

// ========== Временное хранилище пользователей ==========
const users = {};

// ========== Настройка Multer для загрузки аватаров ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = 'uploads/';
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath);
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
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// ========== Middleware ==========
app.set('trust proxy', 1); // Важно для работы за reverse proxy
app.use(express.static('public'));
app.use('/uploads', express.static('uploads')); // Для отдачи статических файлов аватаров
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Конфигурация сессий
app.use(session({
  secret: process.env.SESSION_SECRET || 'super_secret_key',
  resave: false,
  saveUninitialized: false, // Изменено на false для безопасности
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
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
  (req, accessToken, refreshToken, profile, done) => {
    try {
      const existingUser = users[profile.id];
      
      if (existingUser && existingUser.registrationComplete) {
        return done(null, existingUser);
      }
      
      // Создаем временный профиль
      users[profile.id] = {
        id: profile.id,
        displayName: profile.displayName,
        email: profile.emails?.[0]?.value || '',
        registrationComplete: false
      };
      
      return done(null, users[profile.id]);
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
passport.deserializeUser((id, done) => {
  const user = users[id] || null;
  done(null, user);
});

// ========== Middleware для проверки регистрации ==========
function checkRegistration(req, res, next) {
  if (req.isAuthenticated() && req.user.registrationComplete) {
    return next();
  }
  
  if (req.isAuthenticated()) {
    return res.redirect('/registration.html');
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
    // Добавлена проверка сессии
    if (req.user && !req.user.registrationComplete) {
      return res.redirect('/registration.html');
    }
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

// ========== API для регистрации ==========
app.post('/api/register', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { firstName, lastName, gender, age, avatar, role } = req.body;
  const userId = req.user.id;
  
  if (!firstName || !lastName || !gender || !age || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  users[userId] = {
    ...users[userId],
    firstName,
    lastName,
    gender,
    age: parseInt(age),
    avatarUrl: avatar || null,
    role,
    registrationComplete: true
  };
  
  res.json({ success: true });
});

// ========== API для работы с профилем пользователя ==========
app.get('/api/user', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ 
      error: 'Not authenticated',
      code: 'UNAUTHORIZED'
    });
  }
  
  if (!req.user.registrationComplete) {
    return res.json({
      id: req.user.id,
      name: req.user.displayName,
      email: req.user.email,
      registrationComplete: false
    });
  }
  
  res.json({
    id: req.user.id,
    displayName: req.user.displayName,
    email: req.user.email,
    firstName: req.user.firstName,
    lastName: req.user.lastName,
    gender: req.user.gender,
    age: req.user.age,
    avatarUrl: req.user.avatarUrl,
    role: req.user.role,
    registrationComplete: true
  });
});

app.put('/api/user', upload.single('avatar'), (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const userId = req.user.id;
  const user = users[userId];
  
  if (!user || !user.registrationComplete) {
    return res.status(403).json({ error: 'User not registered' });
  }
  
  // Обновляем данные
  if (req.body.firstName) user.firstName = req.body.firstName;
  if (req.body.lastName) user.lastName = req.body.lastName;
  if (req.body.gender) user.gender = req.body.gender;
  if (req.body.age) user.age = parseInt(req.body.age);
  if (req.body.role) user.role = req.body.role;
  
  // Обработка аватара (файл имеет приоритет над URL)
  if (req.file) {
    user.avatarUrl = `/uploads/${req.file.filename}`;
  } else if (req.body.avatarUrl) {
    user.avatarUrl = req.body.avatarUrl;
  }
  
  // Обновляем данные в сессии
  req.session.user = user;
  
  res.json({ 
    status: 'success',
    user: user
  });
});

// ========== Защищенные маршруты ==========
app.get('/family.html', checkRegistration, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'family.html'));
});

app.get('/profile.html', checkRegistration, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// ========== Существующие маршруты ==========
app.get('/api/check-update', (req, res) => {
  try {
    const checkUpdate = require('./api/check-update');
    checkUpdate(req, res);
  } catch (error) {
    console.error('Ошибка загрузки API модуля:', error);
    res.status(500).json({ error: "Internal server error" });
  }
});

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

// ========== Запуск сервера ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
  console.log('Конфигурация OAuth:');
  console.log(`- Client ID: ${GOOGLE_CLIENT_ID ? 'установлен' : 'ОШИБКА! Проверьте .env'}`);
  console.log(`- Callback URL: ${CALLBACK_URL}`);
  
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    console.error('ВНИМАНИЕ: Google OAuth credentials не установлены!');
  }
});

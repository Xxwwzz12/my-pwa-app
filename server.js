const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

// ========== Конфигурация Google OAuth ==========
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://my-pwa-app-w519.onrender.com/auth/google/callback';

// ========== Временное хранилище пользователей ==========
const users = {};

// ========== Middleware ==========
app.set('trust proxy', 1); // Важно для работы за reverse proxy
app.use(express.static('public'));
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
    avatar: avatar || 'default-avatar.png',
    role,
    registrationComplete: true
  };
  
  res.json({ success: true });
});

// ========== API для получения данных пользователя ==========
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
    name: req.user.displayName,
    firstName: req.user.firstName,
    lastName: req.user.lastName,
    gender: req.user.gender,
    age: req.user.age,
    avatar: req.user.avatar,
    role: req.user.role,
    registrationComplete: true
  });
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

const express = require('express');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieParser = require('cookie-parser');
require('dotenv').config(); // Загрузка переменных окружения из .env

const app = express();

// ========== Конфигурация Google OAuth ==========
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://my-pwa-app-w519.onrender.com/auth/google/callback';

// ========== Middleware ==========
app.use(express.static('public'));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Конфигурация сессий
app.use(session({
  secret: process.env.SESSION_SECRET || 'super_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 часа
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
    passReqToCallback: true
  },
  (req, accessToken, refreshToken, profile, done) => {
    // Здесь будет логика работы с профилем пользователя
    // Пока просто возвращаем профиль
    return done(null, profile);
  }
));

// Сериализация пользователя
passport.serializeUser((user, done) => {
  done(null, user);
});

// Десериализация пользователя
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// ========== Маршруты аутентификации ==========
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Успешная аутентификация
    res.redirect('/family.html');
  }
);

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// ========== Защищённые маршруты ==========
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      id: req.user.id,
      name: req.user.displayName,
      email: req.user.emails[0].value
    });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
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
});

import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import mongoose from 'mongoose';
import passport from 'passport'; // Перемещено сюда
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'; // Перемещено
import { fileURLToPath } from 'url';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = 10000;

// Middleware
app.use(helmet());
app.use(compression());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Session Configuration
app.use(session({
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60
  }),
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    httpOnly: true, // Добавлен критически важный флаг
    maxAge: 14 * 24 * 60 * 60 * 1000
  }
}));

// Passport Initialization
app.use(passport.initialize());
app.use(passport.session());

// Google Strategy
// Используем единый callback URL из .env
const callbackURL = process.env.CALLBACK_URL || 
  (process.env.NODE_ENV === 'production' 
    ? 'https://my-pwa-app-w519.onrender.com/auth/google/callback'
    : 'http://localhost:10000/auth/google/callback');

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: callbackURL, // Используем переменную
  passReqToCallback: true // Добавляем для гибкости
}, (req, accessToken, refreshToken, profile, done) => {
  console.log('[Google OAuth] Received profile:', profile.id);
  return done(null, {
    id: profile.id,
    email: profile.emails?.[0]?.value || null,
    name: profile.displayName,
    avatar: profile.photos?.[0]?.value || '',
    provider: 'google'
  });
}));
// Serialization
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => {
  if (!user) return done(new Error('User not found'));
  return done(null, user);
});

// Routes
app.get('/session', (req, res) => {
  req.session.views = (req.session.views || 0) + 1;
  res.send(`Views: ${req.session.views}`);
});

app.get('/', (req, res) => {
  res.send('FamilySpace Auth Test Server');
});

// Auth Routes
app.get('/auth/google', 
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/profile')
);

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).send('Unauthorized');
  res.json(req.user);
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Server Error');
});
// Лог для проверки callback URL
console.log('[OAuth Config]');
console.log(`- Client ID: ${process.env.GOOGLE_CLIENT_ID ? '***' + process.env.GOOGLE_CLIENT_ID.slice(-5) : 'MISSING'}`);
console.log(`- Callback URL: ${callbackURL}`);
console.log(`- Environment: ${process.env.NODE_ENV}`);
// Start Server
app.listen(PORT, () => {
  console.log(`✅ Auth server running on http://localhost:${PORT}`);
  console.log(`- Test: http://localhost:${PORT}/auth/google`);
});
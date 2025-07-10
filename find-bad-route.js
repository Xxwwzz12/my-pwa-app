import { pathToRegexp } from 'path-to-regexp';

const routes = [
  '/api/user',
  '/api/upload-avatar',
  '/api/save-profile',
  '/api/subscriptions',
  '/auth/google',
  '/auth/google/callback',
  '/logout',
  '/offline',
  // Добавьте ВСЕ ваши маршруты из server.js
];

routes.forEach(route => {
  try {
    const regex = pathToRegexp(route);
    console.log(`✅ Valid route: ${route}`);
  } catch (error) {
    console.error(`❌ INVALID ROUTE: ${route}`);
    console.error(`Error: ${error.message}`);
  }
});
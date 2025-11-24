// config.js
// Development settings
const dev = {
  API_URL: 'http://localhost:8000',
  WS_URL: 'ws://localhost:8001'
};

// Production settings
const prod = {
  API_URL: 'https://yourdomain.com',
  WS_URL: 'wss://yourdomain.com'
};

// Select based on environment
const config = process.env.NODE_ENV === 'production' ? prod : dev;

export const API_CONFIG = {
  BASE_URL: config.API_URL,
  WS_URL: config.WS_URL
};

export const WS_ENDPOINTS = {
  CHAT: '/ws/chat/',
  NOTIFICATIONS: '/ws/notifications/'
};

export const API_ENDPOINTS = {
  ENCODE: '/api/encode/',
  DECODE: '/api/decode/',
  LOGIN: '/api/auth/login/',
  REGISTER: '/api/auth/register/',
  PROFILE: '/api/profile/'
};
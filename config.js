/**
 * Configuration centralisée et sécurisée
 * COPY THIS FILE TO config.js AND UPDATE WITH YOUR VALUES
 */

module.exports = {
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'production',
  
  // Domaines autorisés CORS
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS ? 
    process.env.ALLOWED_ORIGINS.split(',') : 
    ['http://localhost:3000', 'https://localhost:3000'],
  
  // JWT Secret (à mettre en .env)
  JWT_SECRET: process.env.JWT_SECRET || 'YOUR_SECURE_JWT_SECRET_HERE',
  JWT_EXPIRY: '24h',
  
  // Rate Limiting
  RATE_LIMIT: {
    maxRequests: 100,        // par IP
    timeWindow: 60000,       // 1 minute
    blockDuration: 900000,   // 15 minutes
    maxRequestsPerMessage: 10
  },
  
  // Message TTL
  MESSAGE_TTL: 2 * 60 * 1000,  // 2 minutes
  
  // Audit
  AUDIT: {
    enabled: true,
    maxLogs: 50000,
    logToFile: true,
    logPath: './logs/audit.log'
  },
  
  // Crypto
  CRYPTO: {
    algorithm: 'aes-256-gcm',
    keyLength: 32,
    tagLength: 16
  },
  
  // Security Headers
  SECURITY_HEADERS: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' https://fonts.googleapis.com",
  }
};

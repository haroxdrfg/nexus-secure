# Quick Start Guide

## Requirements

- Node.js 20.0.0 or higher
- npm

## Installation

### Step 1: Clone the repository
```bash
git clone https://github.com/haroxdrfg/nexus-secure.git
cd nexus-secure
```

### Step 2: Install dependencies
```bash
npm install
```

### Step 3: Configure the server
```bash
cp config.example.js config.js
```

Create a `.env` file at the project root with the following variables:
```
JWT_SECRET=your_strong_random_secret_minimum_32_characters
NODE_ENV=production
PORT=3000
ALLOWED_ORIGINS=http://localhost:3000
```

Why `.env` is not included in the repository: the `.env` file contains secrets (JWT signing key, configuration) that must never be public. Each deployment generates its own secrets. The `config.example.js` file serves as a template.

### Step 4: Start the server
```bash
npm start
```

The server starts on port 3000 by default (configurable via PORT in `.env`).

## Running Tests

Unit tests:
```bash
node test-simple.js
```

End-to-end security tests:
```bash
node test-e2e.js
```

## File Overview

- `server.js` - Express server entry point
- `crypto-advanced.js` - Cryptographic operations (ECDH, ECDSA, AES-256-GCM)
- `e2e-secure.js` - Zero-knowledge encrypted message storage
- `forward-secrecy.js` - Per-message key derivation ratchet
- `persistence.js` - HMAC-signed audit logging
- `rate-limiter.js` - Dual-layer request rate limiting
- `database.js` - In-memory storage with integrity checking
- `validators.js` - Input validation and sanitization
- `config.example.js` - Configuration template
- `test-e2e.js` - End-to-end security test suite
- `test-simple.js` - Unit tests
- `nginx-config.conf` - Reverse proxy configuration for production
- `deploy-production.sh` - Production deployment script
- `install-ubuntu.sh` - Ubuntu server setup script

## Production Deployment

1. Set strong `JWT_SECRET` in `.env`
2. Configure `ALLOWED_ORIGINS` to production domain
3. Install TLS certificate
4. Use nginx configuration provided
5. Run `deploy-production.sh` for server setup
6. Check `IMPLEMENTATION.md` for security considerations

## Troubleshooting

If cryptographic operations fail:
- Verify Node.js version is 20.0.0 or higher
- Check that all required npm dependencies are installed
- Run tests to verify crypto module functionality

For rate limiting issues:
- Check IP-based limits in config
- Verify identity-based limits for authenticated users
- Review rate-limiter.js for threshold settings

# Quick Start Guide

## Installation and First Run

### Step 1: Install Dependencies
```bash
npm install
```

### Step 2: Configure Environment
```bash
cp config.example.js config.js
```

Create a `.env` file with:
```
JWT_SECRET=your_strong_random_secret_here_min_32_chars
NODE_ENV=production
PORT=3000
ALLOWED_ORIGINS=http://localhost:3000
```

### Step 3: Start Server
```bash
npm start
```

Server will start on port 3000 (or configured PORT).

## Running Tests

Unit tests:
```bash
node test-simple.js
```

Integration tests:
```bash
node test-e2e.js
```

## Directory Structure

- `server.js` - Main application
- `crypto-advanced.js` - Encryption functions
- `e2e-secure.js` - Zero-knowledge storage
- `forward-secrecy.js` - Per-message key derivation
- `persistence.js` - Audit and logging
- `rate-limiter.js` - Request throttling
- `test-e2e.js` - Security verification tests
- `nginx-config.conf` - Production reverse proxy setup

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

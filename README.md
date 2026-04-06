# NEXUS SECURE - Backend Server

> End-to-End Encrypted Messaging Platform

## Live Application

[Application link will be provided here]

## Overview

NEXUS SECURE is a production-grade backend server for end-to-end encrypted messaging. It implements modern cryptographic protocols to guarantee message confidentiality, integrity, and authenticity using elliptic curve cryptography (ECDH/ECDSA) with forward secrecy.

The server operates on a zero-knowledge model: it stores only opaque encrypted blobs and has no capability to decrypt message contents, even if fully compromised.

## Architecture

### Core Backend Modules

#### Cryptography (`crypto-advanced.js`)
- Elliptic Curve Diffie-Hellman (ECDH) key exchange
- ECDSA digital signatures with SHA-256
- AES-256-GCM authenticated encryption
- Fail-hard error handling: all cryptographic failures throw exceptions

#### End-to-End Storage (`e2e-secure.js`)
- Zero-knowledge server design
- Messages stored as opaque encrypted blobs
- Server cannot decrypt message contents
- Session metadata isolated from encrypted payload
- Security guaranteed even under full server compromise

#### Forward Secrecy (`forward-secrecy.js`)
- Per-message unique key derivation using unidirectional ratchet
- Key compromise isolation: one key does not affect past or future messages
- HMAC-based per-message authentication
- Simplified Double Ratchet pattern (inspired by Signal Protocol)

#### Audit Integrity (`persistence.js`)
- HMAC-signed audit log entries
- Cryptographic tamper detection
- Immutable forensic trail for compliance
- Configurable log retention

### Security Features

**Access Control**
- CORS validation against configurable whitelist
- JWT token-based session management (24-hour expiry)
- Identity-based session isolation

**Rate Limiting** (`rate-limiter.js`)
- IP-based limit: 100 requests per minute
- Identity-based limit: 50 requests per minute
- Dual-layer enforcement (AND logic)
- 15-minute block duration on threshold exceeded

**Message Lifecycle**
- Configurable TTL (default: 2 minutes)
- Automatic message deletion after expiry
- No server-side retention of plaintext

**Transport Security**
- TLS/SSL enforcement in production
- Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- HTTP Strict-Transport-Security with 1-year max-age

## Installation

See [QUICKSTART.md](QUICKSTART.md) for the full setup guide.

### Requirements
- Node.js 20.0.0 or higher
- npm

### Quick Setup

```bash
git clone https://github.com/haroxdrfg/nexus-secure.git
cd nexus-secure
npm install
cp config.example.js config.js
# Edit config.js and create .env with your secrets
npm start
```

## Why .env and config.js are Not in the Repository

The `.env` file and `config.js` contain deployment-specific secrets, primarily the `JWT_SECRET` used to sign authentication tokens. Publishing these would allow any third party to forge authentication tokens and gain unauthorized access. Each deployment must generate its own secrets. The `config.example.js` file documents all required configuration without including real values.

## File Structure

```
.
├── server.js                # Express server entry point
├── config.example.js        # Configuration template (copy to config.js)
├── crypto-advanced.js       # Cryptographic functions
├── e2e-secure.js           # Zero-knowledge encrypted message storage
├── forward-secrecy.js      # Per-message key derivation (ratchet)
├── persistence.js          # HMAC-signed audit logging
├── rate-limiter.js         # Dual-layer request rate limiting
├── validators.js           # Input validation and sanitization
├── database.js             # In-memory storage with integrity check
├── test-e2e.js            # End-to-end security test suite
├── test-simple.js         # Unit tests
├── nginx-config.conf      # Reverse proxy configuration
├── deploy-production.sh   # Production deployment script
├── install-ubuntu.sh      # Ubuntu server setup script
└── package.json           # Dependencies and metadata
```

Files excluded from the repository (see `.gitignore`):
- `config.js` - Contains secrets
- `.env` - Contains secrets
- `logs/` - Runtime audit data
- `node_modules/` - Dependencies (installed via `npm install`)
- `index.html`, `script.js`, `style.css`, `mobile.css` - Frontend (separate project)

## Dependencies

- **express** ^4.18.2 - Web framework
- **cors** ^2.8.5 - Cross-origin resource sharing
- **selfsigned** ^2.1.1 - Self-signed certificate generation for development

## License

MIT

## Version

2.2.0

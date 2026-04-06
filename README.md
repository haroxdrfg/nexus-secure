# NEXUS SECURE - End-to-End Encrypted Messaging

## Overview

NEXUS SECURE is a production-grade end-to-end encrypted messaging platform implementing modern cryptographic protocols. The system ensures message confidentiality, integrity, and authenticity using elliptic curve cryptography (ECDH/ECDSA) with forward secrecy properties.

## Architecture

### Core Components

#### Cryptography Module (`crypto-advanced.js`)
- Elliptic Curve Diffie-Hellman (ECDH) key exchange
- ECDSA digital signatures
- AES-256-GCM authenticated encryption
- Fail-hard error handling for all cryptographic operations

#### End-to-End Storage (`e2e-secure.js`)
- Server-side storage designed for zero-knowledge operation
- Messages stored as opaque encrypted blobs
- Server cannot decrypt message contents
- Session metadata isolation from encrypted data
- Guarantees security even with full server compromise

#### Forward Secrecy (`forward-secrecy.js`)
- Per-message unique key derivation using unidirectional ratchet
- Message independence - key compromise does not affect past or future messages
- HMAC-based message authentication per message
- Simplified Double Ratchet implementation

#### Audit Integrity (`persistence.js`)
- HMAC-signed audit log entries
- Tamper detection with cryptographic verification
- Immutable forensic trail for compliance
- Configurable log retention and rotation

### Security Features

**Access Control**
- CORS validation against whitelist
- JWT token-based session management (24-hour expiry)
- Identity-based session isolation

**Rate Limiting** (`rate-limiter.js`)
- IP-based limiting: 100 requests per minute
- Identity-based limiting: 50 requests per minute
- Dual-layer enforcement using AND logic
- 15-minute block duration for exceeding limits

**Message Lifecycle**
- Configurable TTL (default: 2 minutes)
- Automatic message deletion after expiry
- No server-side retention of plaintext

**Transport Security**
- TLS/SSL enforcement in production
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- HTTP Strict-Transport-Security with 1-year max-age

## Installation

### Prerequisites
- Node.js 20.0.0 or higher
- npm or yarn

### Setup

```bash
npm install
```

### Configuration

Create a `config.js` file from the template:

```bash
cp config.example.js config.js
```

Edit `config.js` and set the following in `.env`:
- `JWT_SECRET`: Strong random string (min. 32 characters)
- `PORT`: Server port (default: 3000)
- `ALLOWED_ORIGINS`: CORS whitelist

## Running the Server

```bash
npm start
```

For development with file watching:
```bash
npm run dev
```

## Testing

### Unit Tests
```bash
node test-simple.js
```

### End-to-End Tests
```bash
node test-e2e.js
```

Test coverage includes:
- Server decryption impossibility verification
- Forward secrecy validation
- Rate limiting effectiveness
- Audit log integrity
- Cryptographic failure handling
- Session initialization security

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User authentication
- `POST /auth/refresh` - Token refresh

### Messaging
- `POST /messages/send` - Send encrypted message
- `GET /messages/:id` - Retrieve encrypted message
- `DELETE /messages/:id` - Delete message

### Session Management
- `POST /session/init` - Initialize E2E session
- `GET /session/info` - Get session metadata

## Security Considerations

### Deployment

1. **Enable HTTPS/TLS** in production
2. **Rotate JWT_SECRET** regularly
3. **Configure nginx or reverse proxy** for additional security
4. Use provided `nginx-config.conf` as reference
5. **Set strong CORS origins** based on deployment domain
6. **Configure log rotation** to manage audit log size

### Environment Variables
All sensitive configuration must be in `.env`:
```
JWT_SECRET=<strong-random-string>
NODE_ENV=production
PORT=3000
ALLOWED_ORIGINS=https://yourdomain.com
```

### Log Management
- Audit logs stored in `logs/audit.log`
- Configure log rotation in production
- Logs contain non-sensitive metadata only
- Encrypted messages never logged

## File Structure

```
.
├── server.js                 # Express server entry point
├── config.example.js         # Configuration template
├── crypto-advanced.js        # Cryptographic functions
├── e2e-secure.js            # End-to-end storage layer
├── forward-secrecy.js       # Per-message key derivation
├── persistence.js           # Audit logging with integrity
├── rate-limiter.js          # Request rate limiting
├── validators.js            # Input validation utilities
├── database.js              # Persistence layer
├── test-e2e.js             # Integration tests
├── test-simple.js          # Unit tests
├── nginx-config.conf       # Reverse proxy configuration
├── deploy-production.sh    # Production deployment script
├── install-ubuntu.sh       # Ubuntu server setup
├── index.html              # Web client
├── script.js               # Client-side logic
├── style.css               # Styling
├── mobile.css              # Mobile responsive styles
├── package.json            # Dependencies and metadata
└── logs/                   # Runtime audit logs
```

## Dependencies

- **express**: ^4.18.2 - Web framework
- **cors**: ^2.8.5 - Cross-origin resource sharing
- **selfsigned**: ^2.1.1 - Self-signed certificate generation

## License

MIT

## Version

2.2.0 - Stable Release

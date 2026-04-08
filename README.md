# NEXUS SECURE

End-to-end encrypted messaging platform with encrypted photo and video support.

## Features

- End-to-end encrypted text messaging (ECDH P-256 + AES-256-GCM + ECDSA)
- Encrypted photo and video sending (AES-256-GCM chunked, 5 MB chunks, up to 100 MB)
- Forward secrecy with per-message key derivation (Double Ratchet pattern)
- Zero-knowledge server: stores only opaque encrypted blobs, cannot decrypt anything
- Media preview in the input area before sending
- Automatic expiry: messages 2 min TTL, media 10 min TTL
- 30 automated tests (20 unit + 10 server)

## Cryptographic Stack

| Layer | Algorithm | Purpose |
|---|---|---|
| Key Exchange | ECDH P-256 | Shared secret derivation |
| Key Derivation | HKDF-SHA256 | AES key from ECDH shared secret |
| Encryption | AES-256-GCM | Authenticated encryption (text + media) |
| Signatures | ECDSA P-256 + SHA-256 | Message and media authenticity |
| Integrity | HMAC-SHA256 | Media envelope integrity, audit log tamper detection |
| Forward Secrecy | Unidirectional ratchet | Per-message unique keys, key compromise isolation |

### Media Encryption Pipeline

1. Sender generates ephemeral ECDH P-256 key pair
2. Shared secret derived via ECDH with recipient public key
3. AES-256 key derived via HKDF-SHA256 from shared secret + random salt
4. Media split into 5 MB chunks, each encrypted with AES-256-GCM (unique IV per chunk)
5. HMAC-SHA256 computed over all encrypted chunks
6. ECDSA signature over the media reference payload
7. Server stores opaque encrypted envelope (cannot read content)
8. Recipient reverses the pipeline using their private key

Supported media types: `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `video/mp4`, `video/webm`.

## Architecture

### Server Modules

- `server.js` - Express HTTPS server, API routes, media storage with TTL
- `crypto-advanced.js` - ECDH key exchange, ECDSA signatures, AES-256-GCM encryption
- `e2e-secure.js` - Zero-knowledge encrypted message storage
- `forward-secrecy.js` - Per-message key derivation ratchet
- `persistence.js` - HMAC-signed audit logging with tamper detection
- `rate-limiter.js` - Dual-layer rate limiting (IP + identity)
- `validators.js` - Input validation and sanitization
- `database.js` - In-memory storage with integrity checks
- `config.example.js` - Configuration template

### Client Modules

- `script.js` - Client-side E2E crypto (Web Crypto API), media encrypt/decrypt, UI logic
- `index.html` - Frontend web application
- `style.css` - Desktop styles
- `mobile.css` - Mobile responsive styles

### Test Modules

- `tests/media-encrypt.js` - Server-side media encryption module (ECDH + AES-256-GCM + HKDF + HMAC)
- `tests/test-media.js` - 20 unit tests for media encryption
- `tests/test-media-server.js` - 10 server integration tests for media API routes

## API Routes

### Text Messages

| Method | Route | Description |
|---|---|---|
| POST | `/api/send` | Send encrypted message |
| GET | `/api/messages/:recipientId` | Retrieve messages for a recipient |

### Media

| Method | Route | Description |
|---|---|---|
| POST | `/api/media/store` | Store encrypted media envelope |
| GET | `/api/media/retrieve/:mediaId` | Retrieve encrypted media envelope |
| DELETE | `/api/media/:mediaId` | Delete a stored media envelope |

## Security

- CORS whitelist validation
- JWT session management (24h expiry)
- Rate limiting: 300 requests/min per IP, 50/min per identity, 15-min block on exceed
- TLS/SSL with auto-generated self-signed certificates
- Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- Content Security Policy with strict source directives
- No server-side plaintext retention

## Installation

### Requirements

- Node.js 20.0.0+
- npm

### Setup

```bash
git clone https://github.com/haroxdrfg/nexus-secure.git
cd nexus-secure
npm install
cp config.example.js config.js
```

Edit `config.js` with your values (JWT secret, allowed origins, rate limits, CSP headers).

```bash
npm start
```

The server starts on HTTPS port 3000 by default.

### Why config.js is Not in the Repository

`config.js` contains deployment-specific secrets (JWT_SECRET, allowed origins). Publishing these would allow forging authentication tokens. Each deployment must generate its own. See `config.example.js` for the required structure.

## Tests

```bash
node tests/test-media.js
node tests/test-media-server.js
```

## Dependencies

- **express** ^4.18.2
- **cors** ^2.8.5
- **selfsigned** ^2.1.1

## License

MIT

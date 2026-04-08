# NEXUS SECURE

NEXUS SECURE is the backend server for an end-to-end encrypted messaging system. It handles identity management, encrypted message routing, encrypted media transfer, audit logging, and rate limiting. The server never has access to plaintext content.

This repository contains only the server-side code. Frontend clients must implement their own UI and call the documented API.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Server Architecture](#server-architecture)
- [Cryptographic Specifications](#cryptographic-specifications)
- [API Reference](#api-reference)
- [Media Encryption](#media-encryption)
- [Rate Limiting](#rate-limiting)
- [Audit System](#audit-system)
- [Testing](#testing)

---

## Requirements

- Node.js >= 20.0.0
- npm

No external database. All storage is in-memory with configurable TTL.

## Installation

```bash
git clone https://github.com/haroxdrfg/nexus-secure.git
cd nexus-secure
npm install
cp config.example.js config.js
```

Edit `config.js` with your own values, then start:

```bash
npm start
```

The server binds on `0.0.0.0` over HTTPS. If no `cert.crt`/`cert.key` files are found, a self-signed RSA 2048-bit certificate is generated automatically (CN=nexus-secure, validity 365 days).

## Configuration

`config.js` is excluded from the repository because it holds secrets. Copy `config.example.js` and fill in your values.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `PORT` | number | `3000` | HTTPS listening port |
| `NODE_ENV` | string | `production` | Environment mode |
| `ALLOWED_ORIGINS` | string[] | `['http://localhost:3000', 'https://localhost:3000']` | CORS whitelist |
| `JWT_SECRET` | string | required | Secret for JWT token signing. Must be unique per deployment |
| `JWT_EXPIRY` | string | `24h` | JWT token lifetime |
| `RATE_LIMIT.maxRequests` | number | `100` | Max requests per IP per time window |
| `RATE_LIMIT.timeWindow` | number | `60000` | Time window in ms (1 minute) |
| `RATE_LIMIT.blockDuration` | number | `900000` | Block duration in ms (15 minutes) |
| `MESSAGE_TTL` | number | `120000` | Message expiry in ms (2 minutes) |
| `AUDIT.enabled` | boolean | `true` | Enable audit logging |
| `AUDIT.maxLogs` | number | `50000` | Max audit log entries in memory |
| `AUDIT.logPath` | string | `./logs/audit.log` | Audit log file path |
| `CRYPTO.algorithm` | string | `aes-256-gcm` | Symmetric encryption algorithm |
| `CRYPTO.keyLength` | number | `32` | AES key length in bytes |
| `CRYPTO.tagLength` | number | `16` | GCM auth tag length in bytes |
| `SECURITY_HEADERS` | object | see below | HTTP security headers applied to every response |

### Security Headers

Applied via middleware on every response:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy` (configurable per deployment)

---

## Server Architecture

### Module Breakdown

| File | Role |
|------|------|
| `server.js` | Express HTTPS server, all API routes, middleware stack, storage class instances |
| `crypto-advanced.js` | ECDH key exchange, ECDSA signatures, AES-256-GCM encrypt/decrypt, HKDF key derivation, fingerprint computation |
| `e2e-secure.js` | Zero-knowledge message storage with per-session isolation, nonce validation, secure wipe on delete |
| `forward-secrecy.js` | Unidirectional key ratchet for per-message key derivation, HMAC-based message authentication |
| `persistence.js` | HMAC-signed audit log persistence, session/identity/message metadata storage, tamper detection |
| `rate-limiter.js` | Dual-layer rate limiting (per-IP and per-identity), automatic blocking with configurable cooldown |
| `validators.js` | Input validation for identity registration, message submission, pairing requests, key format checks |
| `database.js` | In-memory message storage with per-message random encryption key, auto-expiry every 30s, secure wipe |
| `tests/media-encrypt.js` | Server-side media encryption module (ECDH + HKDF + AES-256-GCM chunked + HMAC integrity) |
| `config.example.js` | Configuration template |

### Internal Storage Classes

**SecureMessageStorage** (in `server.js`)
- In-memory `Map` with per-instance random 32-byte master key
- Each message encrypted at rest with AES-256-GCM (random 12-byte IV)
- TTL: 2 minutes, enforced on read and via periodic cleanup (every 60s)
- Deletion overwrites ciphertext with random bytes before removing the entry

**MediaEnvelopeStorage** (in `server.js`)
- In-memory `Map` for encrypted media envelopes
- TTL: 10 minutes
- Validates `mediaId` (string, max 128 chars) and envelope structure before storing
- Periodic cleanup every 60s

**GenericStorage** (in `server.js`)
- General-purpose key-value store for client-defined data
- Timestamp on every entry, prefix-based key listing

**IdentityManager** (in `server.js`)
- Stores participant identity keys, signed prekeys, one-time prekeys
- Fingerprint computed as SHA-256 of the identity public key
- Trust-on-first-use (TOFU) identity change detection
- One-time prekey consumption with automatic replacement

### SSL/TLS

The server requires HTTPS. On first start, if `cert.crt` and `cert.key` do not exist, a self-signed certificate is generated using the `selfsigned` module (RSA 2048-bit, subject CN=nexus-secure, O=NEXUS SECURE, C=FR, 365-day validity). For production, replace these with proper certificates from a CA or use a reverse proxy.

---

## Cryptographic Specifications

### Algorithms Used

| Primitive | Specification | Key Size | Purpose |
|-----------|--------------|----------|---------|
| ECDH | P-256 (prime256v1) | 256-bit | Key agreement between participants |
| ECDSA | P-256 + SHA-256 | 256-bit | Digital signatures for identity and message authenticity |
| AES-256-GCM | NIST SP 800-38D | 256-bit key, 12-byte IV, 16-byte tag | Authenticated encryption for messages and media |
| HKDF | RFC 5869, SHA-256 | 256-bit output | Key derivation from shared secrets |
| HMAC | SHA-256 | 256-bit | Message authentication, audit log integrity, media envelope integrity |
| SHA-256 | FIPS 180-4 | 256-bit | Fingerprinting, hashing |

### Zero-Knowledge Design

The server stores only encrypted blobs. It does not hold, derive, or have access to any private key or plaintext. Even under full server compromise, message content cannot be recovered:

- ECDH key pairs are generated client-side
- Shared secrets are derived client-side
- Encryption and decryption happen client-side
- The server only transports opaque ciphertext

### Forward Secrecy Mechanism

Implemented in `forward-secrecy.js` as a simplified unidirectional ratchet inspired by the Signal Double Ratchet:

```
Initial: chainKey (32 bytes, derived from session master key)

Per message:
  messageKey  = HKDF(chainKey, info='message')   -> used once, then discarded
  chainKey    = HKDF(chainKey, info='chain')      -> replaces previous chain key

Per encryption:
  nonce       = 16 random bytes
  key, iv     = HKDF(messageKey + nonce, info='encryption', 48 bytes) -> split into 32 + 16
  authKey     = HKDF(messageKey + nonce, info='authentication')
  ciphertext  = AES-256-GCM(plaintext, key, iv)
  signature   = HMAC-SHA256(authKey, ciphertext + counter)
```

Each message uses a unique derived key. Compromising one message key does not reveal past or future keys because the chain advances in one direction only and old keys are discarded after use.

Limitations: no out-of-order message support, no ratchet reset via prekey exchange.

### Identity Verification

Identities are fingerprinted as `SHA-256(identityPublicKey)`. The server implements TOFU (Trust On First Use): the first fingerprint seen for a participant is stored, and any subsequent change is flagged. Clients can build a verification flow on top of this using the `deriveEmojis()` function, which maps fingerprint bytes to the NATO phonetic alphabet for human-readable comparison (ALFA through ZULU).

---

## API Reference

All routes are served over HTTPS. Request and response bodies are JSON.

### Identity

**POST** `/api/identity/register`

Register a participant's identity keys.

```json
{
  "participantId": "string (10-128 chars, alphanumeric + _ -)",
  "identityPublicKey": "PEM or base64 public key",
  "signaturePublicKey": "PEM or base64 public key (optional)"
}
```

Response `200`:
```json
{
  "success": true,
  "fingerprint": "hex SHA-256 of identity public key",
  "sas": ["NATO", "phonetic", "words"]
}
```

**GET** `/api/identity/:participantId`

Retrieve a participant's public identity bundle.

Response `200`:
```json
{
  "identityPublicKey": "PEM",
  "signedPrekey": { "publicKey": "PEM", "signature": "hex" },
  "otpKey": { "id": "hex", "key": "hex" },
  "fingerprint": "hex",
  "sas": ["NATO", "words"]
}
```

### Messages

**POST** `/api/messages/store`

Store an encrypted message blob.

```json
{
  "messageId": "string",
  "encryptedData": "string (opaque ciphertext)"
}
```

Response `200`:
```json
{
  "success": true,
  "expiresAt": 1712345678000
}
```

Messages expire after 2 minutes (configurable via `MESSAGE_TTL`). Expired messages are automatically purged.

**GET** `/api/messages/retrieve/:messageId`

Response `200`:
```json
{
  "encryptedData": "string"
}
```

Returns `404` if the message does not exist or has expired.

**DELETE** `/api/messages/:messageId`

Securely deletes a message. Ciphertext is overwritten with random bytes before removal.

Response `200`:
```json
{
  "success": true
}
```

### Media

**POST** `/api/media/store`

Store an encrypted media envelope. Body limit: 150 MB.

```json
{
  "mediaId": "string (max 128 chars)",
  "envelope": {
    "mimeType": "string (must be in ALLOWED_MIME_TYPES)",
    "salt": "base64",
    "ephemeralPub": "PEM (sender's ephemeral ECDH public key)",
    "encrypted": {
      "chunks": [
        { "index": 0, "data": "base64", "iv": "base64", "tag": "base64" }
      ],
      "totalSize": 12345,
      "chunkCount": 1
    },
    "metaHmac": "base64 (HMAC-SHA256 over metadata)"
  }
}
```

Required envelope fields: `mimeType`, `salt`, `ephemeralPub`, `encrypted`, `metaHmac`.

Allowed MIME types: `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `image/heic`, `image/heif`, `video/mp4`, `video/webm`, `video/quicktime`, `video/x-matroska`.

Response `200`:
```json
{
  "success": true,
  "mediaId": "string",
  "expiresIn": "10 min"
}
```

**GET** `/api/media/retrieve/:mediaId`

Response `200`:
```json
{
  "envelope": { ... }
}
```

Returns `404` if the media does not exist or has expired. Media TTL is 10 minutes.

**DELETE** `/api/media/:mediaId`

Response `200`:
```json
{
  "success": true
}
```

### Storage (Generic Key-Value)

**POST** `/api/storage/:key`

```json
{
  "value": "any"
}
```

**GET** `/api/storage/:key`

**GET** `/api/storage/list/:prefix`

Returns all keys matching the given prefix.

**DELETE** `/api/storage/:key`

### System

**GET** `/api/audit/logs`

Returns the last audit log entries with integrity verification status.

**GET** `/api/security/status`

Returns server status, feature flags, and storage counts.

---

## Media Encryption

The media encryption module (`tests/media-encrypt.js`) implements a full pipeline for encrypting photos and videos before they reach the server.

### Pipeline (Sender Side)

1. **Validation** - check MIME type against whitelist, file size <= 100 MB, valid Buffer
2. **Key generation** - generate ephemeral ECDH P-256 key pair (used once, private key never leaves sender)
3. **Key agreement** - `ECDH(ephemeral_private, recipient_public)` produces shared secret
4. **Key derivation** - `HKDF-SHA256(shared_secret, random_salt, info='nexus-media-key')` produces 32-byte AES key
5. **Chunked encryption** - media split into 5 MB chunks, each encrypted with AES-256-GCM using a unique random 12-byte IV
6. **Integrity** - `HMAC-SHA256(aes_key, mimeType + salt + ephemeralPub + chunkCount + totalSize)` computed over metadata
7. **Output** - envelope containing: `mimeType`, `salt`, `ephemeralPub` (PEM), `encrypted` (chunk array), `metaHmac`

### Pipeline (Recipient Side)

1. **Key agreement** - `ECDH(recipient_private, ephemeral_pub_from_envelope)` reconstructs shared secret
2. **Key derivation** - same HKDF with salt from envelope
3. **HMAC verification** - recompute HMAC over metadata, compare with `crypto.timingSafeEqual` (constant-time)
4. **Chunked decryption** - chunks sorted by index, each decrypted with AES-256-GCM
5. **Output** - original media Buffer

### Exported Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `generateMediaKeyPair()` | none | `{ publicKey, privateKey }` (PEM) |
| `deriveAESKey(sharedSecret, salt)` | Buffer, Buffer | 32-byte Buffer |
| `encryptMedia(mediaBuffer, aesKey)` | Buffer, Buffer | `{ chunks[], totalSize, chunkCount }` |
| `decryptMedia(encryptedMedia, aesKey)` | object, Buffer | Buffer |
| `senderEncryptMedia(mediaBuffer, mimeType, recipientPubPEM)` | Buffer, string, string | `{ envelope }` |
| `recipientDecryptMedia(envelope, recipientPrivPEM)` | object, string | Buffer |

### Constants

| Name | Value |
|------|-------|
| `ALLOWED_MIME_TYPES` | `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `image/heic`, `image/heif`, `video/mp4`, `video/webm`, `video/quicktime`, `video/x-matroska` |
| `MAX_MEDIA_SIZE_BYTES` | 104857600 (100 MB) |
| Chunk size | 5242880 (5 MB) |

---

## Rate Limiting

Two independent layers, both must pass for a request to proceed:

| Layer | Limit | Window | Block Duration |
|-------|-------|--------|----------------|
| Per IP | `maxRequests` (default 100) | 60 seconds | 15 minutes |
| Per Identity | `maxRequests / 2` (default 50) | 60 seconds | 15 minutes |

On violation, the server responds with HTTP `429` and a `Retry-After` header. Every successful response includes an `X-RateLimit-Remaining` header.

Identity is extracted from `req.user.sub` (JWT) or `req.body.participantId`.

---

## Audit System

Every significant action is logged with:

- Event type (e.g. `identity_registered`, `session_created`, `message_stored`)
- Participant ID hash (SHA-256, truncated to first 16 hex chars)
- Sanitized details (fields containing `key`, `secret`, or `password` are redacted)
- Timestamp
- HMAC-SHA256 integrity tag

Logs are written to disk as newline-delimited JSON, each line suffixed with its HMAC. The `verifyAuditLogIntegrity()` function re-computes the HMAC to detect any tampering.

---

## Testing

30 automated tests covering the media encryption module and server routes:

```bash
# 20 unit tests: key generation, HKDF derivation, chunk encrypt/decrypt,
# full sender/recipient pipeline, HMAC tampering, wrong key rejection,
# MIME whitelist, size limits
node tests/test-media.js

# 10 integration tests: POST/GET/DELETE media routes, MIME rejection,
# missing fields, incomplete envelopes, 404 on unknown media,
# zero-knowledge verification
node tests/test-media-server.js
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `express` | ^4.18.2 | HTTP server and routing |
| `cors` | ^2.8.5 | Cross-origin resource sharing |
| `selfsigned` | ^2.1.1 | Self-signed TLS certificate generation |

All cryptographic operations use the built-in Node.js `crypto` module. No third-party crypto libraries.

---

## License

MIT

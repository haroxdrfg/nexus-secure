# NEXUS SECURE

NEXUS SECURE is the backend server for an end-to-end encrypted messaging system. It handles identity management, encrypted message routing, encrypted media and file transfer, anti-bot enforcement, blind server operations, traffic obfuscation, audit logging, and rate limiting. The server never has access to plaintext content at any point.

This repository contains only the server-side code. Frontend clients are responsible for their own UI and must call the documented API.

---

## Table of Contents

- [What's New](#whats-new)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Server Architecture](#server-architecture)
- [Cryptographic Specifications](#cryptographic-specifications)
- [API Reference](#api-reference)
  - [Identity](#identity)
  - [Messages](#messages)
  - [Media](#media)
  - [File Transfer](#file-transfer)
  - [Blind Server](#blind-server)
  - [Anti-Bot — Proof of Work](#anti-bot--proof-of-work)
  - [Cloudflare Turnstile](#cloudflare-turnstile)
  - [Snowflake Proxy](#snowflake-proxy)
  - [Storage (Generic Key-Value)](#storage-generic-key-value)
  - [System](#system)
- [Module Documentation](#module-documentation)
  - [Media Encryption](#media-encryption)
  - [File Encryption](#file-encryption)
  - [Double Ratchet](#double-ratchet)
  - [Blind Server](#blind-server-1)
  - [Anti-Bot](#anti-bot)
  - [Snowflake](#snowflake)
- [Rate Limiting](#rate-limiting)
- [Audit System](#audit-system)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [License](#license)

---

## What's New

The following modules and routes were added since the initial release. All are active in the current server build.

### Encrypted File Transfer (`file-encrypt.js`)

General-purpose file transfer using the same ECDH + HKDF + AES-256-GCM pipeline as media encryption. Supports files up to 500 MB across a whitelist of 30+ MIME types. Filenames are encrypted alongside the file content. Executable extensions are blocked at the validation layer.

Routes: `POST /api/file/store`, `GET /api/file/retrieve/:fileId`, `DELETE /api/file/:fileId`

### Double Ratchet Algorithm (`double-ratchet.js`)

Full implementation of the Signal Double Ratchet using X25519 for Diffie-Hellman ratchet steps and HKDF-SHA256 for chain and message key derivation. Session setup uses X3DH four-way key agreement with identity keys, signed prekeys, and one-time prekeys. Out-of-order messages are supported through a skipped-key cache (up to 100 keys per session).

### Blind Server (`blind-server.js`)

Three-class module for server-side anonymity. `BlindEnvelopeStore` stores blobs without any plaintext metadata, padded to 1 KB block boundaries, with secure deletion on removal. `MetadataStripper` is an Express middleware that strips identifying headers (IP, user agent, referer) from requests on blind-mode paths. `SealedSender` hides sender identity using an ephemeral X25519 key agreement and AES-256-GCM — the server decrypts the payload without knowing who sent it.

Routes: `POST /api/blind/store`, `GET /api/blind/retrieve/:bucket/:envelopeId`, `DELETE /api/blind/:bucket/:envelopeId`, `POST /api/blind/seal`, `POST /api/blind/unseal`, `GET /api/blind/server-key`

### Anti-Bot (`anti-bot.js`)

Three-layer bot mitigation. `ProofOfWork` issues SHA-256 hash challenges (default difficulty: 4 leading zero bits). `FingerprintThrottle` detects repeated clients via a composite fingerprint of IP + user agent + accept headers, throttling them independently from IP-based limits. `TurnstileVerifier` integrates with Cloudflare Turnstile for human verification with 5-minute token caching.

Routes: `GET /api/pow/challenge`, `POST /api/pow/verify`, `GET /api/turnstile/site-key`, `POST /api/turnstile/verify`

### Snowflake Traffic Obfuscation (`snowflake.js`)

`SnowflakeProxy` simulates a Tor Snowflake-style WebRTC proxy to disguise network traffic. `TrafficShaper` normalizes observable throughput and inter-packet timing using configurable patterns (`video-call`, `social-scroll`, `browsing`).

Routes: `POST /api/snowflake/enable`, `POST /api/snowflake/disable`, `GET /api/snowflake/status`, `POST /api/snowflake/connect`, `POST /api/snowflake/relay`, `POST /api/snowflake/disconnect`, `POST /api/snowflake/shape`, `GET /api/snowflake/patterns`

### Dual HTTP/HTTPS Server

The server now binds on both HTTPS (port 3000) and HTTP (port 3001) simultaneously. The HTTP listener is intended for use behind a local reverse proxy. HTTPS remains the required transport for all production traffic.

---

## Requirements

- Node.js >= 20.0.0
- npm

No external database. All storage is in-memory with configurable TTL. A Cloudflare account is required only if Turnstile is used in production.

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

The server binds on `0.0.0.0`. If no `cert.crt`/`cert.key` files are found, a self-signed RSA 2048-bit certificate is generated automatically (CN=nexus-secure, validity 365 days).

## Configuration

`config.js` is excluded from the repository. Copy `config.example.js` and fill in your values.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `PORT` | number | `3000` | HTTPS listening port. HTTP binds on `PORT + 1` |
| `NODE_ENV` | string | `production` | Environment mode |
| `ALLOWED_ORIGINS` | string[] | `['https://localhost:3000']` | CORS whitelist |
| `JWT_SECRET` | string | required | JWT signing secret. Must be unique per deployment |
| `JWT_EXPIRY` | string | `24h` | JWT token lifetime |
| `RATE_LIMIT.maxRequests` | number | `100` | Max requests per IP per window |
| `RATE_LIMIT.timeWindow` | number | `60000` | Rate limit window in ms |
| `RATE_LIMIT.blockDuration` | number | `900000` | IP block duration in ms |
| `MESSAGE_TTL` | number | `120000` | Message expiry in ms |
| `AUDIT.enabled` | boolean | `true` | Enable audit logging |
| `AUDIT.maxLogs` | number | `50000` | Max audit entries in memory |
| `AUDIT.logPath` | string | `./logs/audit.log` | Audit log file path |
| `CRYPTO.algorithm` | string | `aes-256-gcm` | Symmetric cipher |
| `CRYPTO.keyLength` | number | `32` | AES key length in bytes |
| `CRYPTO.tagLength` | number | `16` | GCM auth tag length in bytes |
| `TURNSTILE.siteKey` | string | test key | Cloudflare Turnstile site key (or env var `TURNSTILE_SITE_KEY`) |
| `TURNSTILE.secretKey` | string | test key | Cloudflare Turnstile secret key (or env var `TURNSTILE_SECRET_KEY`) |

For production, set real Turnstile keys from `dash.cloudflare.com`. The built-in test keys accept any token without actual verification.

### Security Headers

Applied on every response:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy` — includes `https://challenges.cloudflare.com` for the Turnstile widget

---

## Server Architecture

### Module Breakdown

| File | Role |
|------|------|
| `server.js` | Express HTTPS/HTTP server, all API routes, middleware stack, storage instances |
| `crypto-advanced.js` | ECDH key exchange, ECDSA signatures, AES-256-GCM, HKDF, fingerprint computation |
| `e2e-secure.js` | Zero-knowledge message storage, per-session isolation, nonce validation, secure wipe |
| `forward-secrecy.js` | Unidirectional key ratchet, per-message key derivation, HMAC-based authentication |
| `double-ratchet.js` | Double Ratchet with X25519 DH ratchet, HKDF chain keys, X3DH four-way key agreement |
| `file-encrypt.js` | File transfer: ECDH + HKDF + AES-256-GCM chunked, filename encryption, MIME whitelist |
| `blind-server.js` | Blind envelope store with blob padding, metadata stripper middleware, sealed sender |
| `anti-bot.js` | SHA-256 proof-of-work, fingerprint throttle, Cloudflare Turnstile verification |
| `snowflake.js` | Snowflake-style WebRTC proxy simulation, traffic shaping patterns |
| `persistence.js` | HMAC-signed audit log persistence, tamper detection |
| `rate-limiter.js` | Per-IP and per-identity rate limiting with automatic blocking |
| `validators.js` | Input validation for identity, messages, pairing, and key formats |
| `database.js` | In-memory message storage with per-message encryption key, auto-expiry, secure wipe |
| `tests/media-encrypt.js` | Media encryption module (ECDH + HKDF + AES-256-GCM chunked + HMAC) |
| `config.example.js` | Configuration template |

### Middleware Stack

Requests pass through the following layers in order:

1. CORS — origin whitelist enforcement
2. Security headers — HSTS, CSP, X-Frame-Options
3. JSON body parser — 10 MB default limit (overridden per route for file and blind endpoints)
4. Static file serving — serves frontend from project root
5. Rate limiter — per-IP and per-identity
6. Fingerprint throttle — composite browser fingerprint rate limiting
7. Metadata stripper — removes identifying headers on `/api/blind/` paths
8. Payload size guard — rejects bodies over 1 MB on standard routes
9. Route handlers

### Internal Storage Classes

**SecureMessageStorage** (`server.js`)
- In-memory `Map` with a random 32-byte master key generated at startup
- Each message encrypted at rest with AES-256-GCM and a random 12-byte IV
- TTL: 2 minutes, enforced on read and on a 60-second cleanup cycle
- On deletion, ciphertext is overwritten with random bytes before the entry is removed

**MediaEnvelopeStorage** (`server.js`)
- Shared in-memory `Map` for both encrypted media and encrypted file envelopes
- TTL: 2 minutes
- Validates ID length and required envelope fields before storing
- Periodic cleanup every 60 seconds

**GenericStorage** (`server.js`)
- General-purpose key-value store
- Timestamp on every entry, prefix-based key listing

**IdentityManager** (`server.js`)
- Stores identity keys, signed prekeys, and one-time prekeys per participant
- Fingerprint: SHA-256 of the identity public key
- Trust-on-first-use (TOFU): first fingerprint accepted, subsequent changes flagged
- One-time prekey consumption with replacement notification

**BlindEnvelopeStore** (`blind-server.js`)
- In-memory `Map` keyed by `bucket:envelopeId`
- Blobs padded to 1 KB block boundaries with random bytes before storage
- TTL: 10 minutes with 60-second cleanup
- Secure deletion overwrites the stored value before removing the map entry

### SSL/TLS

The server requires HTTPS. On first start, if `cert.crt` and `cert.key` are absent, a self-signed certificate is generated (RSA 2048-bit, CN=nexus-secure, O=NEXUS SECURE, C=FR, 365-day validity). For production, replace these with CA-issued certificates or terminate TLS at a reverse proxy.

---

## Cryptographic Specifications

### Algorithms Used

| Primitive | Specification | Key Size | Purpose |
|-----------|--------------|----------|---------|
| ECDH | P-256 (prime256v1) | 256-bit | Key agreement for media and file envelopes |
| X25519 | RFC 7748 | 255-bit | Double Ratchet DH steps, sealed sender, Snowflake peer keys |
| Ed25519 | RFC 8032 | 255-bit | Signed prekey signatures in X3DH |
| ECDSA | P-256 + SHA-256 | 256-bit | Identity and message authenticity signatures |
| AES-256-GCM | NIST SP 800-38D | 256-bit key, 12-byte IV, 16-byte tag | Authenticated encryption throughout |
| HKDF | RFC 5869, SHA-256 | 256-bit output | Key derivation (session keys, ratchet chains, file keys) |
| HMAC | SHA-256 | 256-bit | Message authentication, audit log integrity, envelope metadata |
| SHA-256 | FIPS 180-4 | 256-bit | Fingerprinting, PoW challenges |

### Zero-Knowledge Design

The server stores only encrypted blobs. It does not hold or derive any private key, and cannot access plaintext content. Under full server compromise:

- ECDH and X25519 key pairs are generated client-side
- Shared secrets and AES keys are derived client-side
- Encryption and decryption happen client-side
- The server stores and routes opaque ciphertext only

The blind server mode adds a further layer: sender identity is concealed from the server itself through the sealed sender mechanism.

### Forward Secrecy (forward-secrecy.js)

A simplified unidirectional ratchet, one key per message:

```
chainKey(n+1) = HKDF(chainKey(n), info='chain')
messageKey(n) = HKDF(chainKey(n), info='message')  -> used once, then discarded

nonce  = 16 random bytes
key,iv = HKDF(messageKey + nonce, info='encryption', 48 bytes) -> split 32 + 16
authKey = HKDF(messageKey + nonce, info='authentication')
ciphertext = AES-256-GCM(plaintext, key, iv)
signature  = HMAC-SHA256(authKey, ciphertext + counter)
```

Compromising a single message key does not reveal past or future keys. The chain advances in one direction; old keys are not retained.

### Double Ratchet (double-ratchet.js)

**X3DH session initialization** (four DH operations with X25519):

```
DH1 = X25519(initiator_identity_priv,  responder_signed_prekey_pub)
DH2 = X25519(initiator_ephemeral_priv, responder_identity_pub)
DH3 = X25519(initiator_ephemeral_priv, responder_signed_prekey_pub)
DH4 = X25519(initiator_ephemeral_priv, responder_one_time_prekey_pub)

masterSecret = HKDF(DH1 || DH2 || DH3 || DH4, info='x3dh-master-secret', 32 bytes)
```

**Ratchet operation** (per message):

```
# DH ratchet step (on receiving from a new ratchet key):
dhOutput              = X25519(current_ratchet_priv, peer_ratchet_pub)
rootKey, chainKey     = HKDF-KDF_RK(rootKey, dhOutput)

# Chain key step (per message):
messageKey = HMAC-SHA256(chainKey, 0x01)
chainKey   = HMAC-SHA256(chainKey, 0x02)

# Encryption:
iv, key    = HKDF(messageKey, nonce, info='double-ratchet-message', 44 bytes)
ciphertext = AES-256-GCM(plaintext, key, iv)
```

### Sealed Sender (blind-server.js)

```
# Server generates once at startup:
server_kp = X25519 key pair

# Client seals:
eph_kp       = new X25519 key pair
shared       = X25519(eph_priv, server_pub)
aesKey, iv   = HKDF(shared, random_salt, info='sealed-sender', 44 bytes)
sealed       = AES-256-GCM({ bucket, payload, timestamp }, aesKey, iv)
envelope     = { ephemeralPub, salt, sealed, iv, authTag }

# Server unseals:
shared       = X25519(server_priv, ephemeralPub)
aesKey, iv   = HKDF(shared, salt, info='sealed-sender', 44 bytes)
plaintext    = AES-256-GCM-Decrypt(sealed, aesKey, iv, authTag)
```

The server obtains the payload and the destination bucket but not the sender's identity.

### Identity Verification

Fingerprints are `SHA-256(identityPublicKey)`. The `deriveEmojis()` function maps fingerprint bytes to the NATO phonetic alphabet (ALFA through ZULU) for human-readable out-of-band comparison.

---

## API Reference

All routes are served over HTTPS. Request and response bodies are JSON.

### Identity

**POST** `/api/identity/register`

```json
{
  "participantId": "string (10-128 chars, alphanumeric + _ -)",
  "identityPublicKey": "PEM or base64",
  "signaturePublicKey": "PEM or base64 (optional)"
}
```

Response `200`:
```json
{ "success": true, "fingerprint": "hex", "sas": ["NATO", "words"] }
```

**GET** `/api/identity/:participantId`

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

---

### Messages

**POST** `/api/messages/store`

```json
{ "messageId": "string", "encryptedData": "string" }
```

Response `200`: `{ "success": true, "expiresAt": 1712345678000 }`

TTL: 2 minutes.

**GET** `/api/messages/retrieve/:messageId`

Response `200`: `{ "encryptedData": "string" }` — `404` if expired or not found.

**DELETE** `/api/messages/:messageId`

Ciphertext is overwritten with random bytes before removal.

---

### Media

**POST** `/api/media/store` — body limit: 150 MB

```json
{
  "mediaId": "string (max 128 chars)",
  "envelope": {
    "mimeType": "string",
    "salt": "base64",
    "ephemeralPub": "PEM",
    "encrypted": {
      "chunks": [{ "index": 0, "data": "base64", "iv": "base64", "tag": "base64" }],
      "totalSize": 12345,
      "chunkCount": 1
    },
    "metaHmac": "base64"
  }
}
```

Allowed MIME types: `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `image/heic`, `image/heif`, `video/mp4`, `video/webm`, `video/quicktime`, `video/x-matroska`.

Response `200`: `{ "success": true, "mediaId": "string", "expiresIn": 120000 }`

**GET** `/api/media/retrieve/:mediaId` — Response `200`: `{ "envelope": { ... } }`

**DELETE** `/api/media/:mediaId`

---

### File Transfer

**POST** `/api/file/store` — body limit: 500 MB

```json
{
  "fileId": "string",
  "envelope": {
    "mimeType": "string",
    "salt": "base64",
    "ephemeralPub": "PEM",
    "encrypted": {
      "chunks": [{ "index": 0, "iv": "base64", "authTag": "base64", "ciphertext": "base64", "size": 1024 }],
      "totalSize": 1024,
      "chunkCount": 1
    },
    "encryptedFileName": { "encryptedName": "base64", "iv": "base64", "tag": "base64" },
    "metaHmac": "base64"
  }
}
```

All six envelope fields are required. The server validates the MIME type against the allowed set before storing.

Allowed MIME types include: `application/pdf`, archive formats (zip, 7z, rar, tar, gz), Office formats (docx, xlsx, pptx), `application/json`, `text/plain`, `text/csv`, common image formats, `video/mp4`, `video/webm`, audio formats (mp3, ogg, wav), `application/octet-stream`.

Response `200`: `{ "success": true, "fileId": "string", "expiresIn": 120000 }`

**GET** `/api/file/retrieve/:fileId` — Response `200`: `{ "envelope": { ... } }` — `404` if expired.

**DELETE** `/api/file/:fileId`

---

### Blind Server

**GET** `/api/blind/server-key`

Returns the server's static X25519 public key, required for sealed sender encryption on the client.

Response `200`: `{ "publicKey": "base64 DER" }`

**POST** `/api/blind/store` — body limit: 150 MB

```json
{ "bucket": "string (max 64)", "envelopeId": "string (max 128)", "blob": "string" }
```

Response `200`: `{ "stored": true, "expiresIn": 600000 }`

**GET** `/api/blind/retrieve/:bucket/:envelopeId` — Response `200`: `{ "blob": "string" }`

**DELETE** `/api/blind/:bucket/:envelopeId`

**POST** `/api/blind/seal`

```json
{ "sender": "string", "bucket": "string", "payload": "any" }
```

Response `200`: sealed envelope object.

**POST** `/api/blind/unseal`

Body: sealed envelope as returned by `/api/blind/seal` or produced client-side.

Response `200`: `{ "bucket": "string", "payload": "any", "timestamp": 0 }`

---

### Anti-Bot — Proof of Work

**GET** `/api/pow/challenge`

Response `200`:
```json
{ "challenge": "hex", "difficulty": 4, "expiresAt": 1712345678000 }
```

The client must find a nonce such that `SHA-256(challenge + nonce)` has `difficulty` leading zero bits.

**POST** `/api/pow/verify`

```json
{ "challenge": "hex", "nonce": "string" }
```

Response `200`: `{ "success": true, "hash": "hex" }` — `403` if invalid or expired.

---

### Cloudflare Turnstile

**GET** `/api/turnstile/site-key`

Response `200`: `{ "siteKey": "string" }`

**POST** `/api/turnstile/verify`

```json
{ "token": "string" }
```

Response `200`: `{ "success": true }` or `{ "success": false, "reason": "string" }`.

Verified tokens are cached for 5 minutes to reduce upstream requests.

---

### Snowflake Proxy

**POST** `/api/snowflake/enable`

Response `200`: `{ "status": "enabled", "broker": "url", "stunServers": ["..."] }`

**POST** `/api/snowflake/disable`

Disables the proxy and disconnects all active peers.

**GET** `/api/snowflake/status`

Response `200`:
```json
{
  "enabled": true,
  "activePeers": 1,
  "maxPeers": 5,
  "stats": { "totalRelayed": 0, "bytesRelayed": 0, "peakPeers": 1 }
}
```

**POST** `/api/snowflake/connect`

Response `200`: `{ "peerId": "hex", "sdpOffer": "string", "iceCandidate": "string" }`

Returns `400` if Snowflake is disabled or the 5-peer limit is reached.

**POST** `/api/snowflake/relay`

```json
{ "peerId": "hex", "data": "string" }
```

**POST** `/api/snowflake/disconnect`

```json
{ "peerId": "hex" }
```

**GET** `/api/snowflake/patterns`

Returns available traffic shaping pattern names.

**POST** `/api/snowflake/shape`

```json
{ "pattern": "video-call" }
```

Available patterns: `video-call`, `social-scroll`, `browsing`.

---

### Storage (Generic Key-Value)

**POST** `/api/storage/:key` — `{ "value": "any" }`

**GET** `/api/storage/:key`

**GET** `/api/storage/list/:prefix` — returns all keys matching the prefix

**DELETE** `/api/storage/:key`

---

### System

**GET** `/api/audit/logs`

Returns the last 100 audit log entries with integrity verification status.

**GET** `/api/security/status`

Returns runtime feature flags, active module states, and storage counts. The Snowflake entry reflects current runtime state (Active / Standby).

---

## Module Documentation

### Media Encryption

Module: `tests/media-encrypt.js`

ECDH + HKDF + AES-256-GCM pipeline for photos and videos. Maximum size: 100 MB. Chunk size: 5 MB.

**Sender pipeline:**
1. Validate MIME type and file size
2. Generate ephemeral ECDH P-256 key pair (private key never leaves the sender)
3. `ECDH(ephemeral_priv, recipient_pub)` → shared secret
4. `HKDF-SHA256(shared_secret, salt_32B, info='nexus-media-key')` → 32-byte AES key
5. Encrypt each 5 MB chunk independently with AES-256-GCM and a random 12-byte IV
6. `HMAC-SHA256(aes_key, mimeType + salt + ephemeralPub + chunkCount + totalSize)` over metadata
7. Output: `{ mimeType, salt, ephemeralPub, encrypted: { chunks[], totalSize, chunkCount }, metaHmac }`

**Recipient pipeline:**
1. `ECDH(recipient_priv, ephemeral_pub)` → reconstruct shared secret
2. Derive AES key with same HKDF parameters
3. Verify HMAC with `crypto.timingSafeEqual` (constant-time)
4. Sort chunks by index, decrypt each with AES-256-GCM
5. Output: original media buffer

**Exported functions:**

| Function | Parameters | Returns |
|----------|-----------|---------|
| `generateMediaKeyPair()` | — | `{ publicKey, privateKey }` PEM |
| `deriveAESKey(sharedSecret, salt)` | Buffer, Buffer | 32-byte Buffer |
| `encryptMedia(buffer, aesKey)` | Buffer, Buffer | `{ chunks[], totalSize, chunkCount }` |
| `decryptMedia(encryptedMedia, aesKey)` | object, Buffer | Buffer |
| `senderEncryptMedia(buffer, mimeType, recipientPubPEM)` | Buffer, string, string | `{ envelope }` |
| `recipientDecryptMedia(envelope, recipientPrivPEM)` | object, string | Buffer |

---

### File Encryption

Module: `file-encrypt.js`

Same ECDH + HKDF + AES-256-GCM pipeline as media encryption, extended for arbitrary files. Maximum size: 500 MB. Filenames are encrypted with the same derived AES key.

**Additional validation:**
- Filename: 1–255 characters
- Blocked extensions: `.exe`, `.bat`, `.cmd`, `.com`, `.scr`, `.pif`, `.msi`, `.vbs`, `.js`, `.ws`, `.wsf`, `.ps1`, `.sh`
- MIME type must be in the server whitelist (30+ types)

**Exported functions:**

| Function | Parameters | Returns |
|----------|-----------|---------|
| `generateFileKeyPair()` | — | `{ publicKey, privateKey }` PEM |
| `deriveFileAESKey(sharedSecret, salt)` | Buffer, Buffer | 32-byte Buffer |
| `encryptFile(buffer, aesKey)` | Buffer, Buffer | `{ chunks[], totalSize, chunkCount }` |
| `decryptFile(encryptedFile, aesKey)` | object, Buffer | Buffer |
| `encryptFileName(fileName, aesKey)` | string, Buffer | `{ encryptedName, iv, tag }` base64 |
| `decryptFileName(encName, aesKey)` | object, Buffer | string |
| `senderEncryptFile(buffer, mimeType, fileName, recipientPubPEM)` | Buffer, string, string, string | `{ envelope }` |
| `recipientDecryptFile(envelope, recipientPrivPEM)` | object, string | `{ fileBuffer, fileName, mimeType }` |

---

### Double Ratchet

Module: `double-ratchet.js`

Implements the Signal Double Ratchet specification. X25519 is used for all Diffie-Hellman operations. Sessions are established via X3DH.

**Exported functions:**

| Function | Description |
|----------|-------------|
| `generateIdentityKeyPair()` | X25519 key pair (DER buffers) |
| `generateSignedPreKey(identityPriv)` | Signed prekey with Ed25519 signature |
| `generateOneTimePreKeys(count)` | Array of one-time prekeys |
| `initiatorX3DH(initiatorKeys, responderBundle)` | Initiator X3DH → `{ masterSecret, ephemeralPublicKey }` |
| `responderX3DH(responderKeys, initiatorEphPub, otpKeyId)` | Responder X3DH → `{ masterSecret }` |
| `initSession(masterSecret, role)` | Initialize a Double Ratchet session |
| `encryptMessage(session, plaintextBuffer)` | Encrypt, advance ratchet → `{ header, ciphertext, nonce, authTag }` |
| `decryptMessage(session, header, ciphertext, nonce, authTag)` | Decrypt, handle ratchet steps and skipped keys |

---

### Blind Server

Module: `blind-server.js`

**BlindEnvelopeStore** — opaque blob storage. Blobs are padded to 1 KB block boundaries with cryptographically random bytes before being stored. Secure deletion overwrites the in-memory value before removing the map entry. TTL: 10 minutes.

**MetadataStripper** — Express middleware applied to `/api/blind/` paths. Strips the following headers before route handlers execute: `x-forwarded-for`, `x-real-ip`, `x-forwarded-host`, `cf-connecting-ip`, `user-agent`, `referer`, `origin`, `via`.

**SealedSender** — hides sender identity at the protocol level. The server holds a static X25519 key pair generated at startup. Clients retrieve the server's public key via `GET /api/blind/server-key`, encrypt their payload under it using an ephemeral X25519 key agreement, and submit the sealed envelope. The server decrypts to obtain the payload and destination bucket, but cannot determine who sent it.

---

### Anti-Bot

Module: `anti-bot.js`

**ProofOfWork** — issues 32-byte hex challenges. Clients must find a nonce such that `SHA-256(challenge + nonce)` has `difficulty` leading zero bits. Challenges expire after 10 minutes. Verified solutions are rejected if reused.

**FingerprintThrottle** — Express middleware. Computes a composite fingerprint from IP + User-Agent + Accept-Language + Accept-Encoding. Maintains an independent request counter per fingerprint. This catches clients that rotate IP addresses while keeping an identical browser environment.

**TurnstileVerifier** — submits Turnstile widget tokens to `https://challenges.cloudflare.com/turnstile/v0/siteverify` over HTTPS with a 5-second timeout. Successful verifications are cached in memory for 5 minutes to avoid redundant upstream calls.

---

### Snowflake

Module: `snowflake.js`

**SnowflakeProxy** — simulates a Tor Snowflake WebRTC bridge. Supports up to 5 concurrent peer connections (configurable). Each peer is assigned an X25519 key pair and tracked with per-peer byte counters. Produces synthetic SDP offers and ICE candidates for simulation purposes.

**TrafficShaper** — applies configurable timing parameters to normalize observable traffic patterns:

| Pattern | Behavior |
|---------|----------|
| `video-call` | Constant-bitrate mimicry, small regular intervals |
| `social-scroll` | Bursty, irregular inter-packet delays |
| `browsing` | Request-response cadence with idle gaps |

---

## Rate Limiting

Three independent layers, all must pass for a request to proceed:

| Layer | Limit | Window | Block Duration |
|-------|-------|--------|----------------|
| Per IP | `maxRequests` (default 100) | 60 seconds | 15 minutes |
| Per Identity | `maxRequests / 2` (default 50) | 60 seconds | 15 minutes |
| Per Fingerprint | configurable | configurable | configurable |

On violation: HTTP `429` with `Retry-After` header. All successful responses include `X-RateLimit-Remaining`.

Identity is extracted from `req.user.sub` (JWT) or `req.body.participantId`.

---

## Audit System

Every significant action is logged with:

- Event type (`identity_registered`, `message_stored`, `file_store`, `blind_store`, etc.)
- Participant ID hash (SHA-256, truncated to 16 hex chars)
- Sanitized details (fields named `key`, `secret`, or `password` are redacted)
- Timestamp
- HMAC-SHA256 integrity tag

Logs are written to disk as newline-delimited JSON. Each line is appended with its HMAC. The `verifyAuditLogIntegrity()` function recomputes HMACs to detect any post-write modification.

---

## Testing

```bash
# Unit tests: media encryption module
node tests/test-media.js

# Integration tests: media routes
node tests/test-media-server.js

# Full end-to-end suite
node test-e2e.js

# Smoke tests
node test-simple.js
```

The end-to-end suite covers identity registration, message store/retrieve/delete, media encryption pipeline, file transfer routes, blind server store and seal/unseal, PoW challenge and verification, Turnstile token verification, and Snowflake enable/connect/relay/disconnect.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `express` | ^4.18.2 | HTTP server and routing |
| `cors` | ^2.8.5 | Cross-origin resource sharing |
| `selfsigned` | ^2.1.1 | Self-signed TLS certificate generation |

All cryptographic operations use the built-in Node.js `crypto` module. No third-party cryptographic libraries.

---

## License

MIT

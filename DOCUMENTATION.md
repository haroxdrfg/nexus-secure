# NEXUS SECURE - Technical Documentation

**Version**: 2.2.0  
**Date**: April 2026  
**Repository**: https://github.com/haroxdrfg/nexus-secure  

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [File Reference](#3-file-reference)
4. [Security Model](#4-security-model)
5. [Strengths](#5-strengths)
6. [Weaknesses and Known Limitations](#6-weaknesses-and-known-limitations)
7. [Installation and Setup](#7-installation-and-setup)
8. [Why Certain Files Are Excluded](#8-why-certain-files-are-excluded)
9. [Integrating a Web Frontend](#9-integrating-a-web-frontend)
10. [Deployment in Production](#10-deployment-in-production)
11. [Live Application](#11-live-application)

---

## 1. Project Overview

NEXUS SECURE is a backend server for end-to-end encrypted (E2E) messaging. It is written in Node.js and provides a REST API for applications that need strong privacy guarantees.

The central design principle is zero-knowledge: the server processes and stores messages without being able to read them. Even if the server is fully compromised by an attacker, the plaintext content of any message remains inaccessible.

The project implements three independent layers of cryptographic protection:

1. **End-to-end encryption** - Messages are encrypted by the client before being sent to the server. The server stores only an opaque binary blob and has no access to the encryption key.

2. **Forward secrecy** - Each message is encrypted with a unique key derived from a ratchet. Compromising any single message key does not compromise past or future messages.

3. **Audit integrity** - All server-side events are logged with an HMAC signature. Any tampering with the logs is detectable.

---

## 2. Architecture

### Overview

```
Client A                  Server (NEXUS SECURE)               Client B
--------                  ----------------------               --------
Generate ECDH keys        
Send public key    -----> Store public key hash  <-----   Generate ECDH keys
Derive shared secret       (server never sees key)           Derive shared secret
Encrypt message    -----> Store encrypted blob   ------>   Decrypt message
(AES-256-GCM)             (server cannot decrypt)           (AES-256-GCM)
```

### Request Flow

1. Client registers an identity (ECDH public key, ECDSA signing key)
2. Client A initiates a session with Client B
3. Client A encrypts a message using the shared ECDH secret (never sent to server)
4. Encrypted blob is sent to server via POST /messages/send
5. Server stores blob, validates format, logs the event
6. Client B retrieves the blob via GET /messages/:id
7. Client B decrypts using their own derived shared secret
8. Message is deleted from server after TTL expires

### Module Dependencies

```
server.js
├── config.js              (configuration)
├── validators.js          (input validation)
├── rate-limiter.js        (request throttling)
├── database.js            (storage and audit)
├── crypto-advanced.js     (cryptographic primitives)
├── e2e-secure.js          (depends on crypto-advanced.js)
└── forward-secrecy.js     (depends on node:crypto)

persistence.js             (standalone audit integrity module)
```

---

## 3. File Reference

### `server.js`

**Role**: Entry point of the application.

This file creates the Express server and wires all modules together. It handles:

- HTTPS setup (self-signed certificate for development using the `selfsigned` library)
- Security middleware: CORS enforcement, security headers, rate limiting
- Route definitions for identity registration, session management, and messaging
- Identity management via an in-memory `IdentityManager` class
- Error handling middleware

Key design decisions in this file:

- CORS is configured from `config.js`, not hardcoded, allowing per-deployment configuration
- All headers are injected from a centralized configuration object
- The rate limiter is applied globally before any route logic runs
- Input validation via `validators.js` is applied at the route level before business logic

### `crypto-advanced.js`

**Role**: Cryptographic primitives used throughout the backend.

This module exposes a class `CryptoAdvanced` with static methods. All methods are synchronous and throw on failure (fail-hard pattern, no silent errors).

Methods:
- `computeIdentityFingerprint(publicKey)` - Computes a SHA-256 hash of a public key for use as a stable identity reference. The actual key is never stored.
- `generateSignedPrekey()` - Generates an ECDH key pair on the `prime256v1` curve (P-256). Returns public key, private key, and a signature.
- `generateOneTimePrekeys(count)` - Generates N one-time prekeys for initial key exchange.
- `detectIdentityChange(participantId, newFingerprint, history)` - Detects if a participant has changed their identity key, which could indicate a man-in-the-middle or a key rotation.
- `signData(privateKeyPem, data)` - Signs data using ECDSA with SHA-256. Throws if signing fails.
- `verifySignature(publicKeyPem, data, signature)` - Verifies an ECDSA signature. Throws if verification fails or the signature is invalid.
- `computeSharedSecret(privateKeyPem, publicKeyPem)` - Performs ECDH and derives a 32-byte shared secret using HKDF-SHA256. Throws if the computation fails.

Why fail-hard: Silent failures in cryptography are dangerous. If signature verification fails silently, a forged message could be accepted. Every cryptographic failure results in a thrown exception that propagates to the request handler and returns an error to the client.

### `e2e-secure.js`

**Role**: Server-side message storage layer with zero-knowledge design.

This module exposes the class `E2ESecureStorage`. It is the core of the zero-knowledge server design.

Methods:
- `initializeSession(participantId, peerId, clientECDHPublicKey, clientECDHPrivateKey)` - Creates session metadata on the server. The server stores a hash of the public key, not the key itself, and never the private key.
- `storeMessage(messageId, sessionId, encryptedBlob, nonce)` - Receives an already-encrypted blob from the client and stores it. The server has no knowledge of the plaintext or the encryption key.
- `retrieveMessage(messageId, sessionId)` - Returns the stored blob to the requesting client. The server simply relays the blob without processing it.
- `deleteMessage(messageId)` - Removes the message from storage permanently.
- `getSessionInfo(sessionId)` - Returns non-sensitive session metadata (creation time, message count, etc.).

Why this matters: A traditional server that stores messages can be compelled (legally or through attack) to disclose message contents. This server cannot comply because it never possessed the keys needed to decrypt.

### `forward-secrecy.js`

**Role**: Per-message key derivation using a ratchet mechanism.

This module exposes `ForwardSecrecyRatchet`. It is initialized with a 32-byte session master key and a starting counter.

How it works:

1. The ratchet holds a `chainKey` (starts as the master key).
2. For each message, two values are derived using HKDF-SHA256:
   - `messageKey = HKDF(chainKey, "", "message", 32)` - Used to encrypt/decrypt this specific message.
   - `newChainKey = HKDF(chainKey, "", "chain", 32)` - Becomes the new chain key for the next message.
3. The old chain key is discarded.
4. The message counter is incremented.

Properties:
- **Unidirectional**: Given the current chain key, it is possible to derive future keys but not reverse-compute past keys. This is the core forward secrecy property.
- **Key isolation**: Each message key is derived independently. Disclosing message key #5 does not expose keys #1-4 or #6+.

Methods:
- `deriveNextMessageKey()` - Returns the next message key and the updated counter.
- `encryptWithForwardSecrecy(plaintext)` - Derives a message key, encrypts using AES-256-GCM, and returns the ciphertext and associated metadata.
- `decryptWithForwardSecrecy(encryptedMessage, expectedCounter)` - Verifies the counter, derives the corresponding key, and decrypts.
- `advanceRatchetTo(targetCounter)` - Fast-forwards the ratchet to a specific counter position (for out-of-order message delivery).

### `persistence.js`

**Role**: Audit logging with cryptographic integrity protection.

This module exposes `SecurePersistence`. It provides a persistent store (in-memory with optional file write) for audit logs with tamper detection.

How audit integrity works:

1. A 32-byte HMAC key is generated at server startup using `crypto.randomBytes`.
2. For each log entry, the JSON is serialized and an HMAC-SHA256 is computed over it.
3. Both the entry and its HMAC are written to `logs/audit.log` in the format: `{json}|{hmac}`.
4. On verification, each line is re-read, the HMAC is recomputed, and compared against the stored value. A mismatch indicates tampering.

Data stored:
- Sessions (metadata only, no keys)
- Message records (message ID, session ID, timestamp, size - no content)
- Identity fingerprints (SHA-256 hash of public key, not the key itself)
- Audit log entries

Methods:
- `saveSession(session)` - Persists session metadata.
- `saveMessageRecord(record)` - Persists a message receipt (not the message).
- `saveIdentity(participantId, fingerprint, publicKeyHash)` - Persists an identity record.
- `addAuditLog(entry)` - Appends a signed audit log entry.
- `verifyAuditIntegrity()` - Reads all log entries and verifies their HMAC signatures.
- `generateForensicReport()` - Returns a summary of all stored records for forensic analysis.

### `rate-limiter.js`

**Role**: Two-layer rate limiting for DoS and abuse prevention.

This module exposes `RateLimiter`. It maintains in-memory counters for IP addresses and authenticated user identities with a sliding time window.

Layer 1 - IP-based (from `config.js`):
- Limit: 100 requests per 60-second window per IP
- Block duration: 15 minutes
- Proxy-aware: reads `X-Forwarded-For` header (set by nginx) to extract the real client IP

Layer 2 - Identity-based:
- Limit: 50 requests per 60-second window per authenticated user
- Block duration: 15 minutes

Enforcement logic (AND):
- A request must pass BOTH layers to proceed.
- An IP block stops requests even from authenticated users.
- An identity block stops requests even from unblocked IPs.

This dual enforcement prevents a single user from bypassing IP limits by rotating IPs, and prevents a single IP from bypassing user limits by rotating identities.

Methods:
- `middleware()` - Express middleware function that checks both limits and calls `next()` or returns 429.
- `checkIPLimit(ip)` - Returns `{allowed, reason, retryAfter}`.
- `checkIdentityLimit(participantId)` - Returns `{allowed, reason, retryAfter}`.
- `resetLimitsForTesting()` - Clears all counters (only for test environments).

### `database.js`

**Role**: In-memory storage with audit logging, used directly by `server.js`.

This module contains two classes:
- `AuditLogger` - Writes structured audit entries to `logs/audit.log` with HMAC signatures. Sanitizes all entries before writing (strips values for fields containing `key`, `secret`, or `password`).
- `SecureMessageStorage` - Stores encrypted message blobs in a `Map` with message metadata. Enforces TTL deletion.

`AuditLogger.log(eventType, participantId, details, severity)`:
- The `participantId` is hashed (SHA-256, truncated to 16 hex chars) before logging. The actual ID is never written to disk.
- The `details` object is sanitized to redact cryptographic material.

### `validators.js`

**Role**: Input validation and sanitization for all API endpoints.

All validation is strict and explicit. Input that does not conform to the expected format is rejected before reaching business logic.

Validators:
- `isValidParticipantId(id)` - Alphanumeric + underscore/hyphen, 10-128 characters.
- `isValidPublicKey(key)` - Checks for PEM format, base64, or hex encoding. Length-bounded.
- `isValidMessage(msg)` - Verifies the encrypted message object structure (ciphertext, iv, nonce present and correct type).
- `isValidFingerprint(fp)` - 32-64 hex characters.
- `isValidBase64(str)` - Round-trip base64 check.
- `isValidHex(str, length)` - Regex check with optional length constraint.
- `sanitizeString(str, maxLength)` - Truncates and trims strings that will be used in responses.
- `validateIdentityRegister(body)` - Composite validator for the registration endpoint, returns an array of errors.
- `validateMessageSend(body)` - Composite validator for the message send endpoint.

### `config.example.js`

**Role**: Configuration template. Copy to `config.js` before running.

Documents all required environment variables and their default values. Contains no real secrets; all sensitive fields reference environment variables via `process.env`.

Configuration categories:
- `PORT`, `NODE_ENV` - Server settings
- `ALLOWED_ORIGINS` - CORS whitelist (comma-separated in env)
- `JWT_SECRET`, `JWT_EXPIRY` - Authentication
- `RATE_LIMIT` - Rate limiter thresholds
- `MESSAGE_TTL` - Message expiry
- `AUDIT` - Logging settings
- `CRYPTO` - Cryptographic algorithm parameters
- `SECURITY_HEADERS` - HTTP response headers

### `test-e2e.js`

**Role**: End-to-end security tests verifying critical security properties.

Tests:
1. **Server cannot decrypt** - Stores a message and attempts to access its plaintext. Asserts failure.
2. **Forward secrecy** - Derives two consecutive message keys. Asserts they are not equal and that knowing one does not reveal the other.
3. **Rate limiting** - Sends 110 requests. Asserts that requests beyond the limit return 429.
4. **Audit log integrity** - Writes log entries, modifies the file directly, and asserts that `verifyAuditIntegrity()` detects the tampering.
5. **Cryptographic fail-hard** - Calls `signData()` and `verifySignature()` with invalid inputs. Asserts that exceptions are thrown.
6. **Session initialization** - Initializes a session and asserts that the returned metadata contains no private key material.

### `test-simple.js`

**Role**: Unit tests for individual functions.

Covers input validation, fingerprint computation, rate limiter logic, config structure, and message format validation.

### `nginx-config.conf`

**Role**: Reference nginx configuration for production deployment.

Configures nginx as a reverse proxy in front of the Node.js server:
- HTTPS termination on port 443
- HTTP to HTTPS redirect
- `proxy_pass` to `localhost:3000`
- `X-Forwarded-For` header injection (required by `rate-limiter.js`)
- Security headers
- Rate limiting at the nginx level as an additional layer

### `deploy-production.sh`

**Role**: Shell script for production server provisioning.

Automates: user creation, directory setup, npm install, systemd service configuration, nginx setup, and firewall rules.

### `install-ubuntu.sh`

**Role**: Ubuntu-specific setup script.

Installs Node.js 20, npm, nginx, and configures system prerequisites.

---

## 4. Security Model

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Server compromise | Zero-knowledge storage, server cannot decrypt |
| Key compromise (one message) | Forward secrecy ratchet isolates message keys |
| Log tampering | HMAC-signed log entries with tamper detection |
| Brute force / DoS | Dual-layer rate limiting with block |
| Identity spoofing | ECDSA signatures, fingerprint tracking |
| Replay attacks | Message TTL of 2 minutes, nonce per message |
| Input injection | Strict validators on all endpoints |
| Token forgery | JWT signed with strong secret from env |

### What the Server Knows

The server stores and can access only:
- The hash of a participant's public key (fingerprint)
- Session metadata: who is communicating with whom, when, and how many messages
- Encrypted blobs (no key to decrypt them)
- Audit log entries (sanitized, participant ID hashed)

The server does not and cannot access:
- Any private key
- Any message plaintext
- The shared secrets between participants

---

## 5. Strengths

### Cryptographic Soundness
- Uses well-established algorithms (ECDH P-256, ECDSA, AES-256-GCM, HKDF-SHA256) from the Node.js built-in `crypto` module, which uses OpenSSL. No custom cryptographic implementations.
- All cryptographic operations are fail-hard. There are no code paths that silently pass on failure.

### Zero-Knowledge Architecture
- The server architecture enforces the principle at the code level, not just by policy. The server does not have a code path to decrypt messages because it was never designed to hold the keys.

### Defense in Depth
- Rate limiting at two independent layers (IP and identity)
- Input validation before any logic runs
- Security headers on every response
- Audit logs that can detect tampering

### Audit Trail
- All significant events are logged with a verifiable HMAC
- Even if the system is compromised, the integrity of historical logs can be verified
- Forensic reports can be generated from the stored data

### Minimal Dependencies
- Three production dependencies only: `express`, `cors`, `selfsigned`
- No database dependencies in production configuration (in-memory store)
- Reduced attack surface from third-party packages

---

## 6. Weaknesses and Known Limitations

### In-Memory Storage
- All sessions and messages are stored in JavaScript `Map` objects. A server restart loses all data. There is no persistence between restarts.
- This is acceptable for short-lived messaging where TTL is 2 minutes, but not suitable for applications that need message history.

### Single-Server Architecture
- No horizontal scaling. Sessions are stored in process memory; two server instances cannot share state.
- A load balancer would route different requests to different instances, breaking session continuity.

### In-Memory Rate Limiting
- Rate limit counters are also in-memory. A server restart clears all counters and blocks. An attacker who can force a restart can reset rate limits.

### Simplified Ratchet
- The forward secrecy implementation is described in the code comments as a "simplified Double Ratchet." It provides per-message key derivation but does not implement the full Diffie-Hellman ratchet of the Signal Protocol.
- This means that after a session is established, there is no re-keying via a new ECDH exchange. The security of all messages in a session ultimately depends on the security of the initial session master key.

### Self-Signed Certificate for Development
- The `selfsigned` library generates a self-signed TLS certificate. This is sufficient for development but will trigger browser security warnings. Production deployments must use a certificate from a recognized certificate authority (e.g., Let's Encrypt).

### No Horizontal Scaling or Clustering
- The master secret used for HMAC in `persistence.js` is generated at startup. Different processes have different keys, making audit log verification impossible in a multi-process setup.

### Frontend Not Included
- The web frontend (HTML/CSS/JS) is excluded from this repository. Any web client must implement the client-side cryptography correctly to benefit from the server's security guarantees. See Section 9 for integration guidance.

---

## 7. Installation and Setup

### Requirements

- Node.js 20.0.0 or higher (required for `crypto.hkdfSync`, `generateKeyPairSync`)
- npm 8 or higher

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/haroxdrfg/nexus-secure.git
cd nexus-secure

# 2. Install production dependencies
npm install

# 3. Create configuration
cp config.example.js config.js

# 4. Create environment file
# Create a file named .env in the project root:
echo "JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")" > .env
echo "NODE_ENV=production" >> .env
echo "PORT=3000" >> .env
echo "ALLOWED_ORIGINS=http://localhost:3000" >> .env

# 5. Start the server
npm start
```

The server will output its address and whether it is running over HTTP or HTTPS.

### Configuration Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | Signing key for JWT tokens. Minimum 32 characters. Generate randomly. |
| `NODE_ENV` | Yes | `production` or `development` |
| `PORT` | No | Server port. Default: 3000 |
| `ALLOWED_ORIGINS` | Yes | Comma-separated list of allowed origins for CORS |

---

## 8. Why Certain Files Are Excluded

### `.env` and `config.js`

These files contain `JWT_SECRET`, which is the key used to sign and verify authentication tokens. Anyone with this value can generate valid tokens and impersonate any user.

Publishing `JWT_SECRET` to a public repository would permanently compromise the security of any deployment using that value. Even if the file is later deleted from the repository, the value remains in git history.

The repository provides `config.example.js` which documents all configuration parameters with placeholder values. Each deployment must create its own `config.js` with deployment-specific secrets.

### `logs/`

Audit logs contain runtime data: timestamps of connections, participant ID hashes, message counts. This data is operational and not part of the source code. Logs belong to the deployment, not the repository.

### `node_modules/`

Dependencies are versioned in `package.json`. Anyone cloning the repository runs `npm install` to reproduce the dependency tree. Committing `node_modules/` into a repository adds hundreds of megabytes of generated files that do not belong in version control.

### `index.html`, `script.js`, `style.css`, `mobile.css`

The web frontend is a separate concern from the backend server. These files are excluded because:
1. The frontend will likely be hosted separately (CDN, separate static host)
2. The frontend requires its own versioning and deployment cycle
3. Mixing frontend and backend in one repository complicates both
4. Security review of backend and frontend requires separate contexts

---

## 9. Integrating a Web Frontend

Any web client connecting to this server must implement the client-side cryptography. The server's security guarantees depend on the client doing this correctly.

### Required Client-Side Operations

**1. Key Generation**
The client must generate an ECDH key pair using the Web Crypto API:
```javascript
const keyPair = await window.crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' },
  true,    // extractable
  ['deriveKey', 'deriveBits']
);
```

**2. Key Export for Identity Registration**
```javascript
const publicKeyRaw = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyRaw)));
// POST publicKeyBase64 to /identity/register
```

**3. Shared Secret Derivation**
When communicating with another participant, import their public key and derive the shared secret:
```javascript
const peerPublicKey = await window.crypto.subtle.importKey(
  'spki',
  peerPublicKeyBuffer,
  { name: 'ECDH', namedCurve: 'P-256' },
  false,
  []
);
const sharedBits = await window.crypto.subtle.deriveBits(
  { name: 'ECDH', public: peerPublicKey },
  myPrivateKey,
  256
);
// sharedBits is now your 32-byte session master key
// This key must NEVER be sent to the server
```

**4. Message Encryption (before sending to server)**
```javascript
const iv = window.crypto.getRandomValues(new Uint8Array(12));
const encryptionKey = await window.crypto.subtle.importKey(
  'raw', sharedBits, { name: 'AES-GCM' }, false, ['encrypt']
);
const ciphertext = await window.crypto.subtle.encrypt(
  { name: 'AES-GCM', iv },
  encryptionKey,
  new TextEncoder().encode(plaintext)
);
// Send { ciphertext: base64(ciphertext), iv: base64(iv) } to the server
```

**5. Message Decryption (after receiving from server)**
```javascript
const decrypted = await window.crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: base64ToBuffer(message.iv) },
  encryptionKey,
  base64ToBuffer(message.ciphertext)
);
const plaintext = new TextDecoder().decode(decrypted);
```

### Compatibility Notes

- The Web Crypto API is available in all modern browsers and in Node.js 15+.
- The `P-256` curve (`prime256v1`) used by the server matches the Web Crypto API curve name `P-256`.
- Key formats: the server expects and returns PEM or base64-encoded keys. Export client keys as `spki` (public) and `pkcs8` (private) for compatibility with the server's PEM-based operations.
- The server accepts messages as JSON with `ciphertext`, `iv`, and `nonce` fields. Ensure the client matches this structure as defined in `validators.js`.

---

## 10. Deployment in Production

### Using nginx (recommended)

1. Copy `nginx-config.conf` to `/etc/nginx/sites-available/nexus-secure`
2. Update `server_name` to your domain
3. Add your TLS certificate paths
4. Enable the site: `ln -s /etc/nginx/sites-available/nexus-secure /etc/nginx/sites-enabled/`
5. Test configuration: `nginx -t`
6. Reload: `systemctl reload nginx`

### Running as a system service

The `deploy-production.sh` script creates a systemd unit file. Run it once to configure the service:
```bash
bash deploy-production.sh
systemctl enable nexus-secure
systemctl start nexus-secure
```

### TLS Certificate (Let's Encrypt)

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d yourdomain.com
```

### Security Checklist Before Going Live

- `JWT_SECRET` is a randomly generated value specific to this deployment (minimum 64 hex characters)
- `NODE_ENV=production` is set
- `ALLOWED_ORIGINS` contains only your production domain
- HTTPS is active with a valid certificate
- The `logs/` directory is not publicly accessible
- `config.js` is not in the repository and not accessible via the web server
- Regular log rotation is configured

---

## 11. Live Application

[Link to be added]

---

*This document covers the backend server only. Frontend integration is described in Section 9.*

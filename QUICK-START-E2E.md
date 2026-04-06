# NEXUS SECURE v2.2.0 - Quick Start Integration Guide

> **Status**: All E2E modules complete ✅ | Awaiting server.js integration ⏳

---

## What's New (v2.2.0)

✅ **TRUE End-to-End Encryption**: Server cannot read messages (untrusted model)  
✅ **Forward Secrecy**: Each message has unique key (ratchet-based)  
✅ **Fail-Hard Cryptography**: No silent signature forgeries, errors throw  
✅ **Dual-Rate Limiting**: IP + Identity both enforced  
✅ **HMAC Audit Logs**: Tamper-proof with integrity verification  

---

## 5-Step Integration

### Step 1: Verify All Files Exist ✅

Check that these new files exist:
```bash
ls -la e2e-secure.js           # TRUE E2E storage (350 lines)
ls -la forward-secrecy.js      # Per-message key ratchet (280 lines)
ls -la persistence.js          # HMAC audit logging (300 lines)
ls -la test-e2e.js             # Test suite (350 lines)
ls -la E2E-INTEGRATION-GUIDE.md # Integration pseudo-code
```

### Step 2: Run Test Suite

Verify all security properties work:
```bash
npm install    # Install dependencies if needed
node test-e2e.js
```

**Expected Output**:
```
═══════════════════════════════════════════════════
         NEXUS SECURE v2.2.0 - E2E TEST SUITE
═══════════════════════════════════════════════════

TEST 1: Server Cannot Decrypt Messages
✓ Server stored message without decryption
✓ Retrieved message is still encrypted (opaque)

TEST 2: Forward Secrecy - Per-Message Keys
✓ Each message has unique key
✓ Keys are unidirectional (cannot derive backwards)

TEST 3: Rate Limiting - IP + Identity Dual Layer
✓ Rate limiter enforces IP-based limit (100/min)
✓ Rate limiter enforces identity-based limit (50/min)
✓ Both limits must pass (AND logic)

TEST 4: Audit Log Immutability & HMAC Integrity
✓ Audit logs created with HMAC signatures
✓ HMAC integrity verification passed
✓ Logs are immutable (tampering detected)

TEST 5: Crypto Error Handling (No Silent Failures)
✓ Tampered signature throws error (not silent fail)
✓ Invalid ECDH key throws error (not silent fail)
✓ Input validation rejects malicious payloads

TEST 6: Session Initialization & Metadata
✓ Session created with metadata only
✓ No encryption keys stored on server
✓ Session has expiry (2 hours)

═══════════════════════════════════════════════════
     ALL TESTS PASSED ✓
═══════════════════════════════════════════════════
```

If tests fail, check `package.json` has dependencies: `express`, `eslint`, etc.

### Step 3: Integrate Modules into server.js

#### A) Add Imports (at top of server.js)

**OLD** (remove these):
```javascript
const { AuditLogger, SecureMessageStorage } = require('./database');
```

**NEW** (replace with):
```javascript
const E2ESecureStorage = require('./e2e-secure');
const SecurePersistence = require('./persistence');
const ForwardSecrecyRatchet = require('./forward-secrecy');
const Validators = require('./validators');
const RateLimiter = require('./rate-limiter');

// Initialize E2E components
const persistence = new SecurePersistence('./data/nexus-secure.db');
const e2eStorage = new E2ESecureStorage();
const rateLimiter = new RateLimiter();
const userRatchets = new Map(); // participantId -> ForwardSecrecyRatchet
```

#### B) Add New E2E Endpoints

See `E2E-INTEGRATION-GUIDE.md` for 4 new endpoints:
1. `POST /api/e2e/session/init` - Initialize session (client derives ECDH)
2. `POST /api/e2e/messages/store` - Store encrypted blob (opaque to server)
3. `GET /api/e2e/messages/retrieve/:sessionId/:messageId` - Return encrypted blob
4. `GET /api/audit/logs` - Export audit logs for verification

#### C) Apply Rate Limiting Middleware

Add to global middleware in server.js:
```javascript
app.use((req, res, next) => {
  const check = rateLimiter.checkLimit({
    ip: req.ip,
    participantId: req.body?.participantId || req.query?.participantId
  });
  
  if (!check.allowed) {
    persistence.auditLog('rate_limit_exceeded', req.ip, { reason: check.reason }, 'WARN');
    return res.status(429).json({ error: 'Too many requests' });
  }
  
  next();
});
```

### Step 4: Update Client-Side (script.js, index.html)

#### A) Add ForwardSecrecyRatchet to Client

In `script.js`, after ECDH key agreement:
```javascript
// OLD: Client just sent encrypted message with session key
const encrypted = crypto.encrypt(message, sessionKey);

// NEW: Client uses per-message keys from ratchet
const messageKey = clientRatchet.deriveNextMessageKey(); // Unique per message!
const encrypted = crypto.encrypt(message, messageKey);

// OLD: Send to server
fetch('/api/messages', { body: encrypted });

// NEW: Send encrypted blob + metadata
fetch('/api/e2e/messages/store', {
  body: JSON.stringify({
    sessionId: session.id,
    messageId: generateId(),
    encryptedBlob: encrypted,
    nonce: nonce,
    counter: messageCounter++
  })
});
```

#### B) Update Receive Flow

In `script.js`, when receiving message:
```javascript
// OLD: Server sent plaintext or weakly encrypted
const message = await fetch(`/api/messages/${msgId}`).json();
displayMessage(message.content); // ← Server had plaintext!

// NEW: Server sends opaque encrypted blob, client decrypts
const data = await fetch(`/api/e2e/messages/retrieve/${sessionId}/${msgId}`).json();
const messageKey = clientRatchet_receiver.deriveNextMessageKey();
const plaintext = crypto.decrypt(data.encryptedBlob, messageKey);
displayMessage(plaintext); // ← Only client can open
```

#### C) Update UI Indicators

In `index.html`, add E2E status:
```html
<!-- OLD: No E2E indicator -->
<span id="status">Connected</span>

<!-- NEW: E2E status indicator -->
<span id="e2e-status">
  <span class="badge e2e-active">🔒 E2E Active</span>
  Forward Secrecy: <span class="fw-sec-counter">0</span> keys
</span>

<script>
  // Update counter as messages are sent/received
  let keyCounter = 0;
  document.querySelector('.fw-sec-counter').textContent = keyCounter++;
</script>
```

### Step 5: Deploy & Test

#### A) Local Testing

```bash
npm run dev     # Start development server

# In another terminal, test E2E flow manually:
# 1. Open http://localhost:3000 in two browser windows
# 2. Register user Alice in window 1
# 3. Register user Bob in window 2
# 4. Alice exchanges ECDH with Bob
# 5. Alice sends encrypted message
# 6. Check server audit logs - message stored as opaque blob
# 7. Bob receives and decrypts (only Bob can read)
```

#### B) Verify Encryption

Check that server truly cannot decrypt:
```bash
# 1. Send message via UI (Alice → Bob)
# 2. Check audit log:
tail -f ./logs/audit.log

# Expected output:
# {"timestamp":..., "eventType":"e2e_message_stored", "messageId":"msg_123"}
# Note: NO message content in log (it's encrypted)

# 3. Try to read database directly:
cat ./data/nexus-secure.db | strings | grep -i "hello"
# Should find NOTHING - message is encrypted in database too
```

#### C) Test Rate Limiting

```bash
# Simulate spam from one identity (should block at 50)
for i in {1..60}; do
  curl -X POST http://localhost:3000/api/e2e/messages/store \
    -H "Content-Type: application/json" \
    -d '{"participantId":"alice", "messageId":"test", ...}'
done

# Expected: First 50 succeed, requests 51+ get 429 Too Many Requests
# This prevents one user from flooding even if using multiple IPs
```

---

## File Structure After Integration

```
nexus-secure/
├── server.js            [MODIFIED] Add E2E endpoints
├── script.js            [MODIFIED] Add client-side ratchet
├── index.html           [MODIFIED] Add E2E UI indicators
├── crypto-advanced.js   [✓ DONE] Fail-hard crypto
├── e2e-secure.js        [✓ DONE] Server untrusted storage
├── forward-secrecy.js   [✓ DONE] Per-message key ratchet
├── persistence.js       [✓ DONE] HMAC audit logging
├── rate-limiter.js      [✓ DONE] Dual-layer limiting
├── .env                 [ACTION] Copy .env.example → .env
├── .env.example         [✓ DONE] Updated for v2.2.0
├── test-e2e.js          [✓ READY] Run for verification
├── E2E-INTEGRATION-GUIDE.md    [✓ REFERENCE] Integration details
├── E2E-COMPLETE.md             [✓ REFERENCE] Architecture docs
├── E2E-STATUS-REPORT.md        [✓ REFERENCE] Full status
└── certs/               [AUTO] Self-signed (dev) or Let's Encrypt (prod)
    ├── cert.crt
    └── cert.key
```

---

## Deployment Timeline

### 🟢 Phase 1: Testing (TODAY)
- [ ] Run `node test-e2e.js` ✓
- [ ] Integrate modules into server.js
- [ ] Test local encryption/decryption
- [ ] Verify rate limiting works

### 🟡 Phase 2: Integration (THIS WEEK)
- [ ] Update script.js with ratchet client-side
- [ ] Update index.html with E2E indicators
- [ ] Deploy to staging server
- [ ] Manual end-to-end testing

### 🟠 Phase 3: Hardening (BEFORE PRODUCTION)
- [ ] Register domain (nexus-secure-production.com)
- [ ] Setup DNS A record
- [ ] Configure Let's Encrypt with Certbot
- [ ] Load test rate limiting

### 🔴 Phase 4: Production (LAUNCH)
- [ ] Deploy to production
- [ ] Verify HTTPS with valid certificate
- [ ] Monitor audit logs
- [ ] Public announcement

---

## Key Concepts

### What Server KNOWS:
- Alice has session with Bob (metadata)
- Message sent at 17:30:00 (timing)
- Message is 2048 bytes (size)

### What Server DOES NOT KNOW:
- Message content ✗ (encrypted)
- Encryption key ✗ (never transmitted)
- Shared secret ✗ (ECDH local only)
- Who really sent it ✗ (only session ID)

### If Server Compromised:
- Attacker gets metadata (timing, size, IDs)
- Attacker CANNOT decrypt ✗ (no key)
- Attacker CANNOT forge ✗ (needs private key)
- Attacker CANNOT recover keys ✗ (no storage)

---

## Common Issues & Fixes

### ❌ "Module not found" error

```bash
# Ensure all new files exist
ls -la e2e-secure.js forward-secrecy.js persistence.js

# Ensure imports match filenames exactly (case-sensitive)
grep "require.*e2e-secure" server.js  # Should find the import
```

### ❌ "Cannot find module X after integration"

```bash
# Check that require() paths are correct
# If files are in same directory, use:
const Module = require('./module-name');

# NOT:
const Module = require('./module-name.js');  // Don't add .js
```

### ❌ Test suite fails

```bash
# Check Node.js version (v14+ required)
node --version

# Check dependencies installed
npm ls | grep -E "express|crypto"

# Try clean install
rm -rf node_modules package-lock.json
npm install
node test-e2e.js
```

### ❌ Server starts but E2E endpoints return 404

```bash
# Ensure endpoints added to server.js
grep "e2e/session/init" server.js  # Should find POST handler

# Check server console for errors
npm run dev  # Look for error messages during startup
```

---

## Next Commands

**Today**:
```bash
node test-e2e.js                    # ← Verify all tests pass
cat E2E-INTEGRATION-GUIDE.md         # ← Read integration details
nano server.js                       # ← Start integrating endpoints
```

**This Week**:
```bash
npm install                          # ← Ensure deps ready
npm run dev                          # ← Test locally
npm start                            # ← Start production server
```

**Production**:
```bash
sudo certbot --nginx -d nexus-secure-production.com  # ← Let's Encrypt
npm start                            # ← Deploy
tail -f ./logs/audit.log            # ← Monitor
```

---

## Files for Reference

| File | Purpose |
|------|---------|
| `E2E-INTEGRATION-GUIDE.md` | How to integrate into server.js (pseudo-code) |
| `E2E-COMPLETE.md` | Architecture details (cryptography, design) |
| `E2E-STATUS-REPORT.md` | Full project status and deployment checklist |
| `test-e2e.js` | Run to verify all security properties |
| `.env.example` | Configuration template for deployment |

---

## Success Criteria

✅ Integration Complete When:
- [ ] `node test-e2e.js` returns all tests PASSED ✓
- [ ] Server starts without errors: `npm start`
- [ ] Encryption works end-to-end (test manually)
- [ ] Server audit logs show encrypted blobs (no plaintext)
- [ ] Client-side ratchet generates unique per-message keys
- [ ] Rate limiting blocks spam (test with load)
- [ ] HMAC audit logs verify without tampering

---

## Support

For questions:
1. Check `E2E-INTEGRATION-GUIDE.md` (integration pseudo-code)
2. Check `E2E-COMPLETE.md` (architecture explanation)
3. Run `test-e2e.js` (validates everything works)
4. Review `E2E-STATUS-REPORT.md` (full status + next steps)

**Goal**: All modules integrated by end of this week, production-ready by end of month.

---

**Version**: 2.2.0  
**Last Updated**: April 5, 2026  
**Status**: 🟡 Awaiting Integration  
**Est. Time to Complete**: 3-5 hours integration + 2-3 hours testing

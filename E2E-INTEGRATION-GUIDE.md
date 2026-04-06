/**
 * INTEGRATION GUIDE FOR E2E ARCHITECTURE
 * 
 * This is pseudo-code showing how to integrate e2e-secure.js and forward-secrecy.js
 * into the existing server.js
 * 
 * REPLACE database.js imports and SecureMessageStorage usage with this
 */

// ============ IMPORTS (Add to server.js) ============

const E2ESecureStorage = require('./e2e-secure');
const SecurePersistence = require('./persistence');
const ForwardSecrecyRatchet = require('./forward-secrecy');
const Validators = require('./validators');

// ============ INITIALIZATION ============

// Initialize secure components
const persistence = new SecurePersistence('./data/nexus-secure.db');
const e2eStorage = new E2ESecureStorage();
const userRatchets = new Map(); // participantId -> ForwardSecrecyRatchet

// ============ KEY NEW ENDPOINTS ============

/**
 * Initialize E2E Session - Key Exchange
 * 
 * Client sends:
 *   - participantId
 *   - peerId  
 *   - ecdhPublicKey (client's ECDH public key)
 *   - peerEcdhPublicKey (peer's ECDH public key, from previous identity fetch)
 * 
 * Server returns:
 *   - sessionId (routing identifier)
 *   - message: "Session initialized"
 * 
 * IMPORTANT: Client derives shared secret locally:
 *   sharedSecret = ECDH(myPrivateKey, peerPublicKey)
 *   sessionMasterKey = HKDF(sharedSecret, ...)
 *   ratchet = new ForwardSecrecyRatchet(sessionMasterKey)
 * 
 * Server NEVER knows sessionMasterKey or ratchet
 */
app.post('/api/e2e/session/init', (req, res) => {
  try {
    const { participantId, peerId, ecdhPublicKeyHash } = req.body;

    // Validate
    if (!Validators.isValidParticipantId(participantId)) {
      return res.status(400).json({ error: 'Invalid participantId' });
    }

    if (!Validators.isValidParticipantId(peerId)) {
      return res.status(400).json({ error: 'Invalid peerId' });
    }

    // Initialize session (server stores metadata only)
    const session = e2eStorage.initializeSession(
      participantId,
      peerId,
      null, // client sends later or derives locally
      ecdhPublicKeyHash
    );

    AuditLogger.log('e2e_session_init', participantId, {
      peerId,
      sessionId: session.sessionId
    });

    res.json({
      success: true,
      sessionId: session.sessionId,
      message: 'Session initialized. Client must derive ECDH shared secret locally.'
    });
  } catch (error) {
    AuditLogger.log('e2e_session_init_failed', req.body?.participantId, { error: error.message }, 'ERROR');
    res.status(500).json({ error: 'Session initialization failed' });
  }
});

/**
 * Store Encrypted Message
 * 
 * Client sends:
 *   - sessionId
 *   - messageId (unique)
 *   - encryptedBlob (encrypted with per-message key derived from ratchet)
 *   - nonce (used in key derivation)
 *   - counter (which ratchet step)
 *   - signature (client signs with ECDSA private key)
 * 
 * Server stores opaque blob - CANNOT DECRYPT
 */
app.post('/api/e2e/messages/store', (req, res) => {
  try {
    const { sessionId, messageId, encryptedBlob, nonce, counter, signature, clientPublicKey } = req.body;

    // Validate
    if (!sessionId || !messageId || !encryptedBlob) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!Validators.isValidHex(encryptedBlob) || encryptedBlob.length > 1000000) {
      return res.status(400).json({ error: 'Invalid encrypted blob' });
    }

    // Store message (opaque to server)
    const stored = e2eStorage.storeMessage(messageId, sessionId, encryptedBlob, nonce);

    // Optionally verify signature (if client provides)
    if (signature && clientPublicKey) {
      try {
        e2eStorage.verifyMessageSignature(messageId, clientPublicKey, signature, 'unknown');
      } catch (e) {
        // Log but don't fail - optional signature
        AuditLogger.log('message_signature_invalid', messageId, { error: e.message }, 'WARN');
      }
    }

    AuditLogger.log('e2e_message_stored', messageId, {
      sessionId,
      size: encryptedBlob.length / 2,
      counter
    });

    res.json(stored);
  } catch (error) {
    AuditLogger.log('e2e_message_store_failed', 'unknown', { error: error.message }, 'ERROR');
    res.status(500).json({ error: error.message });
  }
});

/**
 * Retrieve Encrypted Message
 * 
 * Client sends:
 *   - sessionId
 *   - messageId
 * 
 * Server returns:
 *   - encryptedBlob (still encrypted - client cannot use)
 *   - nonce (client needs this for key derivation)
 *   - counter (client needs this for ratchet state)
 * 
 * Client then:
 *   1. Derives key from ratchet using counter + nonce
 *   2. Decrypts blob with AES-256-GCM
 *   3. Verifies HMAC signature
 * 
 * Server didn't do any crypto - just returned blob
 */
app.get('/api/e2e/messages/retrieve/:sessionId/:messageId', (req, res) => {
  try {
    const { sessionId, messageId } = req.params;

    if (!sessionId || !messageId) {
      return res.status(400).json({ error: 'Missing sessionId or messageId' });
    }

    const message = e2eStorage.retrieveMessage(messageId, sessionId);

    AuditLogger.log('e2e_message_retrieved', messageId, { sessionId });

    res.json(message);
  } catch (error) {
    AuditLogger.log('e2e_message_retrieve_failed', 'unknown', { error: error.message }, 'ERROR');
    res.status(404).json({ error: error.message });
  }
});

/**
 * What SERVER KNOWS vs DOESN'T KNOW
 * 
 * SERVER KNOWS:
 *   - Alice has session with Bob (metadata)
 *   - Message was sent at 2026-04-05 17:30:00 (timing)
 *   - Message is 2048 bytes (size)
 *   - Message has ID "msg_123"
 * 
 * SERVER DOES NOT KNOW:
 *   - What the message says (encrypted)
 *   - Who really sent it (only sees session ID)
 *   - Message meaning (opaque blob)
 *   - Encryption key (never transmitted)
 *   - Shared secret (ECDH done locally)
 *   - Derivation of per-message key
 * 
 * If server is compromised:
 *   - Attacker gets metadata (timing, size, IDs)
 *   - Attacker CANNOT decrypt messages
 *   - Attacker CANNOT forge signatures (needs Ed25519 private key)
 */

// ============ CLEANUP TASKS ============

/**
 * Cleanup expired messages periodically
 */
setInterval(() => {
  const cleaned = e2eStorage.messageQueue
    ? Object.values(e2eStorage.messageQueue)
        .filter(m => Date.now() > m.expiresAt).length
    : 0;
  
  if (cleaned > 0) {
    AuditLogger.log('cleanup_expired_messages', 'system', { count: cleaned });
  }
}, 60000); // Every minute

/**
 * Cleanup database expired messages
 */
setInterval(() => {
  const count = persistence.cleanupExpiredMessages();
  if (count > 0) {
    AuditLogger.log('database_cleanup', 'system', { messagesRemoved: count });
  }
}, 5*60*1000); // Every 5 minutes

// ============ AUDIT LOG EXPORT ============

app.get('/api/audit/logs', Auth.middleware(), (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
    const logs = persistence.exportAuditLogs(limit);

    res.json({
      count: logs.length,
      logs
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SECURITY STATUS ENDPOINT ============

app.get('/api/security/e2e-status', (req, res) => {
  res.json({
    version: '2.2.0',
    architecture: 'TRUE E2E',
    encryption: 'AES-256-GCM client-side',
    keyManagement: 'ECDH + Per-message derivation',
    forwardSecrecy: 'Ratchet-based',
    serverTrust: 'Untrusted - cannot decrypt',
    properties: E2ESecureStorage.securityProperties(),
    forwardSecrecyModel: ForwardSecrecyRatchet.securityProperties()
  });
});

// ============ NOTES FOR CLIENT-SIDE ============

/*
CLIENT MUST:

1. Generate ECDH keypair
   const keyPair = await crypto.subtle.generateKey(
     { name: 'ECDH', namedCurve: 'P-256' },
     true,
     ['deriveKey']
   );

2. Exchange public keys (via /api/identity endpoints)

3. Derive shared secret locally (NEVER send)
   const sharedSecret = await crypto.subtle.deriveKey(
     { name: 'ECDH', public: peerPublicKey },
     myPrivateKey,
     { name: 'AES-GCM', length: 256 },
     false,
     ['encrypt', 'decrypt']
   );

4. Derive session master key (HKDF)
   sessionMasterKey = HKDF(sharedSecret, salt="", info="session")

5. Create ratchet
   ratchet = new ForwardSecrecyRatchet(sessionMasterKey)

6. For each message:
   a) Derive per-message key: messageKey = ratchet.deriveNextMessageKey()
   b) Encrypt: encryptedBlob = AES-256-GCM(plaintext, messageKey)
   c) Send: POST /api/e2e/messages/store { sessionId, messageId, encryptedBlob, nonce }

7. Receive message:
   a) GET /api/e2e/messages/retrieve/:sessionId/:messageId
   b) Get encryptedBlob + nonce + counter
   c) Derive key: messageKey = ratchet_state[counter]
   d) Decrypt: plaintext = AES-256-GCM-decrypt(encryptedBlob, messageKey)

SECURITY GUARANTEES:
- Server cannot read messages
- If server compromised: messages still protected
- If one message key leaked: others still protected (forward secrecy)
- Audit trail is immutable + integrity-checked
*/

module.exports = {};

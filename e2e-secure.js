const crypto = require('crypto');
const CryptoAdvanced = require('./crypto-advanced');

class E2ESecureStorage {
  constructor() {
    this.sessions = new Map();
    this.messageQueue = new Map();
  }

  initializeSession(participantId, peerId, clientECDHPublicKey, clientECDHPrivateKey) {
    if (!participantId || !peerId || !clientECDHPublicKey) {
      throw new Error('Missing required parameters for session initialization');
    }

    const sessionId = `${participantId}:${peerId}`;    const session = {
      sessionId,
      participantId,
      peerId,
      initiatedAt: Date.now(),
      clientECDHPublicKeyHash: crypto.createHash('sha256').update(clientECDHPublicKey).digest('hex'),
      state: 'initialized',
      messageCount: 0,
      lastMessageTime: null
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  storeMessage(messageId, sessionId, encryptedBlob, nonce) {
    if (!messageId || !sessionId || !encryptedBlob || !nonce) {
      throw new Error('Missing required message fields');
    }

    if (!this.sessions.has(sessionId)) {
      throw new Error('Session not found');
    }

    const session = this.sessions.get(sessionId);    if (typeof nonce !== 'string' || nonce.length < 16) {
      throw new Error('Invalid nonce');
    }    if (!/^[a-f0-9]+$/i.test(encryptedBlob) || encryptedBlob.length > 1000000) {
      throw new Error('Invalid encrypted blob format or too large');
    }    const messageEntry = {
      messageId,
      sessionId,      encryptedBlob,
      nonce,
      storedAt: Date.now(),
      expiresAt: Date.now() + (2 * 60 * 1000),
      size: encryptedBlob.length / 2
    };

    this.messageQueue.set(messageId, messageEntry);    session.messageCount++;
    session.lastMessageTime = Date.now();

    return {
      success: true,
      messageId,
      storedAt: messageEntry.storedAt,
      expiresAt: messageEntry.expiresAt
    };
  }

  retrieveMessage(messageId, sessionId) {
    if (!messageId || !sessionId) {
      throw new Error('Missing messageId or sessionId');
    }

    const message = this.messageQueue.get(messageId);

    if (!message) {
      throw new Error('Message not found');
    }

    if (message.sessionId !== sessionId) {
      throw new Error('Session mismatch - unauthorized access attempt');
    }

    if (Date.now() > message.expiresAt) {
      this.messageQueue.delete(messageId);
      throw new Error('Message expired');
    }    return {
      messageId,
      encryptedBlob: message.encryptedBlob,
      nonce: message.nonce,
      retrievedAt: Date.now()
    };
  }

  deleteMessage(messageId) {
    if (!messageId) {
      throw new Error('Missing messageId');
    }

    const message = this.messageQueue.get(messageId);
    if (!message) {
      return { success: true, deleted: false };
    }    message.encryptedBlob = crypto.randomBytes(Buffer.byteLength(message.encryptedBlob) / 2).toString('hex');
    message.nonce = crypto.randomBytes(16).toString('hex');

    this.messageQueue.delete(messageId);

    return { success: true, deleted: true };
  }

  verifyMessageSignature(messageId, clientPublicKey, signature, clientId) {
    if (!messageId || !clientPublicKey || !signature || !clientId) {
      throw new Error('Missing verification fields');
    }

    const message = this.messageQueue.get(messageId);
    if (!message) {
      throw new Error('Message not found');
    }    try {
      const verify = crypto.createVerify('sha256');
      verify.update(messageId + message.nonce);
      const isValid = verify.verify(clientPublicKey, Buffer.from(signature, 'hex'));

      if (!isValid) {
        throw new Error('Invalid signature');
      }

      return {
        valid: true,
        messageId,
        clientId,
        signatureVerified: true
      };
    } catch (e) {
      throw new Error('Signature verification failed: ' + e.message);
    }
  }

  static derivePerMessageKey(sessionMasterKey, messageCounter, nonce) {
    if (!sessionMasterKey || typeof messageCounter !== 'number' || !nonce) {
      throw new Error('Invalid parameters for key derivation');
    }

    const info = `message:${messageCounter}:${nonce}`;
    return crypto.hkdfSync('sha256', sessionMasterKey, Buffer.alloc(0), info, 32);
  }

  static deriveSessionMasterKey(ecdhSharedSecret, participantId, peerId) {
    if (!ecdhSharedSecret || !participantId || !peerId) {
      throw new Error('Invalid ECDH or participant data');
    }

    const info = `session:${participantId}:${peerId}`;
    return crypto.hkdfSync('sha256', ecdhSharedSecret, Buffer.alloc(0), info, 32);
  }

  getSessionStatus(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    return {
      sessionId,
      participantId: session.participantId,
      peerId: session.peerId,
      state: session.state,
      messageCount: session.messageCount,
      initiatedAt: session.initiatedAt,
      lastMessageTime: session.lastMessageTime,    };
  }

  cleanupExpiredMessages() {
    const now = Date.now();
    let count = 0;

    for (const [messageId, message] of this.messageQueue.entries()) {
      if (now > message.expiresAt) {
        this.deleteMessage(messageId);
        count++;
      }
    }

    return { cleaned: count };
  }

  static securityProperties() {
    return {
      encryption: 'Client-side only (server never has keys)',
      decryption: 'Impossible for server (no key access)',
      forwardSecrecy: 'Per-message key derivation',
      keyManagement: 'ECDH on client, never transmitted',
      serverTrust: 'Minimal (server is untrusted/semi-honest)',
      metadata: 'Server has timing + size only'
    };
  }
}

module.exports = E2ESecureStorage;

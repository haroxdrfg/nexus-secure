/**
 * Forward Secrecy Implementation
 * 
 * Simplified Double Ratchet pattern:
 * - Each message gets a unique key derived from session master key + message counter
 * - If one message key is compromised, others remain secure
 * - Ratchet is advanced after each message (similar to Signal Protocol)
 * 
 * Not true Signal Protocol (which is much more complex)
 * But provides forward secrecy without per-message ECDH
 */

const crypto = require('crypto');

class ForwardSecrecyRatchet {
  constructor(sessionMasterKey, counterStart = 0) {
    if (!sessionMasterKey || sessionMasterKey.length !== 32) {
      throw new Error('Invalid session master key');
    }

    this.masterKey = sessionMasterKey;
    this.chainKey = sessionMasterKey.copy();
    this.messageCounter = counterStart;
    this.ratchetHistory = []; // For debugging / analysis only
  }

  /**
   * Derive next message key
   * 
   * Process:
   * 1. messageKey = HKDF(chainKey, "", "message")
   * 2. chainKey = HKDF(chainKey, "", "chain")
   * 3. counter++
   * 
   * Similar to Signal's symmetric ratchet
   */
  deriveNextMessageKey() {
    // Derive message key from current chain key
    const messageKey = crypto
      .hkdfSync('sha256', this.chainKey, Buffer.alloc(0), 'message', 32);

    // Advance chain key (ratchet forward)
    const newChainKey = crypto
      .hkdfSync('sha256', this.chainKey, Buffer.alloc(0), 'chain', 32);

    this.chainKey = newChainKey;
    this.messageCounter++;

    // Record for auditing
    this.ratchetHistory.push({
      counter: this.messageCounter - 1,
      timestamp: Date.now(),
      keyLength: messageKey.length
    });

    return {
      messageKey,
      counter: this.messageCounter - 1,
      chainKey: this.chainKey // Never send to server
    };
  }

  /**
   * Get current chain key (never sent to server or peer)
   */
  getChainKey() {
    return this.chainKey.copy();
  }

  /**
   * Get message counter (metadata only)
   */
  getCounter() {
    return this.messageCounter;
  }

  /**
   * Derive per-message encryption key
   * 
   * Takes the message key and derives actual encryption params
   */
  static deriveEncryptionParams(messageKey, nonce) {
    if (!messageKey || messageKey.length !== 32) {
      throw new Error('Invalid message key');
    }

    if (!nonce || nonce.length !== 16) {
      throw new Error('Invalid nonce');
    }

    // Derive encryption key and IV from message key + nonce
    const encParams = crypto.hkdfSync(
      'sha256',
      messageKey,
      nonce,
      'encryption',
      48 // 32 bytes key + 16 bytes IV
    );

    return {
      key: encParams.slice(0, 32),
      iv: encParams.slice(32, 48)
    };
  }

  /**
   * Derive HMAC key for authentication
   */
  static deriveAuthKey(messageKey, nonce) {
    return crypto.hkdfSync(
      'sha256',
      messageKey,
      nonce,
      'authentication',
      32
    );
  }

  /**
   * Encrypt message with forward secrecy
   * 
   * Returns: {
   *   counter (public),
   *   ciphertext (encrypted with per-message key),
   *   iv (public),
   *   nonce (public),
   *   tag (HMAC for auth)
   * }
   */
  encryptMessage(plaintext, additionalData = '') {
    if (typeof plaintext !== 'string' && !Buffer.isBuffer(plaintext)) {
      throw new Error('Invalid plaintext');
    }

    // Derive next message key from ratchet
    const { messageKey, counter } = this.deriveNextMessageKey();
    const nonce = crypto.randomBytes(16);

    // Get encryption params
    const { key, iv } = ForwardSecrecyRatchet.deriveEncryptionParams(messageKey, nonce);

    // Encrypt with AES-256-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (additionalData) {
      cipher.setAAD(Buffer.from(additionalData));
    }

    const ciphertext = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
    const tag = cipher.getAuthTag();

    // Derive auth key and signature
    const authKey = ForwardSecrecyRatchet.deriveAuthKey(messageKey, nonce);
    const signature = crypto
      .createHmac('sha256', authKey)
      .update(ciphertext + counter.toString())
      .digest('hex');

    return {
      counter,
      ciphertext,
      iv: iv.toString('hex'),
      nonce: nonce.toString('hex'),
      tag: tag.toString('hex'),
      signature,
      timestamp: Date.now()
    };
  }

  /**
   * Decrypt message
   * 
   * Requires knowing the message key (only possible if you're in the conversation)
   * Server cannot decrypt because it doesn't have messageKey
   */
  static decryptMessage(encryptedPacket, messageKey) {
    if (!encryptedPacket || !messageKey) {
      throw new Error('Invalid decryption parameters');
    }

    const { ciphertext, iv, nonce, tag, signature } = encryptedPacket;

    // Verify inputs
    if (!ciphertext || !iv || !nonce || !tag || !signature) {
      throw new Error('Missing decryption packet fields');
    }

    // Derive decryption params
    const { key, iv: deriveIv } = ForwardSecrecyRatchet.deriveEncryptionParams(
      messageKey,
      Buffer.from(nonce, 'hex')
    );

    // Verify signature before decoding
    const authKey = ForwardSecrecyRatchet.deriveAuthKey(messageKey, Buffer.from(nonce, 'hex'));
    const expectedSignature = crypto
      .createHmac('sha256', authKey)
      .update(ciphertext + encryptedPacket.counter.toString())
      .digest('hex');

    if (signature !== expectedSignature) {
      throw new Error('Invalid signature - message tampering detected');
    }

    // Decrypt
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, deriveIv);
    decipher.setAuthTag(Buffer.from(tag, 'hex'));

    const plaintext = decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');

    return {
      plaintext,
      counter: encryptedPacket.counter,
      timestamp: encryptedPacket.timestamp
    };
  }

  /**
   * Get ratchet history for analysis
   * Shows how many messages have been encrypted
   */
  getHistory(limit = 100) {
    return this.ratchetHistory.slice(-limit);
  }

  /**
   * Security properties of this ratchet
   */
  static securityProperties() {
    return {
      name: 'Simplified Double Ratchet',
      forwardSecrecy: 'Per-message key derivation',
      backwardSecrecy: 'Ratchet advances, old chainKeys not derivable',
      authentication: 'HMAC-SHA256 on ciphertext',
      encryption: 'AES-256-GCM',
      keyDerivation: 'HKDF-SHA256',
      complexity: 'Medium (not full Signal Protocol)',
      limitations: [
        'No out-of-order message support',
        'No session forgetting',
        'No prekey exchange variant'
      ]
    };
  }
}

module.exports = ForwardSecrecyRatchet;

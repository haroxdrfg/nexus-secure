const crypto = require('crypto');

class ForwardSecrecyRatchet {
  constructor(sessionMasterKey, counterStart = 0) {
    if (!sessionMasterKey || sessionMasterKey.length !== 32) {
      throw new Error('Invalid session master key');
    }

    this.masterKey = sessionMasterKey;
    this.chainKey = Buffer.from(sessionMasterKey);
    this.messageCounter = counterStart;
    this.ratchetHistory = [];
  }

  deriveNextMessageKey() {
    const messageKey = crypto
      .hkdfSync('sha256', this.chainKey, Buffer.alloc(0), 'message', 32);
    const newChainKey = crypto
      .hkdfSync('sha256', this.chainKey, Buffer.alloc(0), 'chain', 32);

    this.chainKey = newChainKey;
    this.messageCounter++;
    this.ratchetHistory.push({
      counter: this.messageCounter - 1,
      timestamp: Date.now(),
      keyLength: messageKey.length
    });

    return {
      messageKey,
      counter: this.messageCounter - 1,
      chainKey: this.chainKey
    };
  }

  getChainKey() {
    return Buffer.from(this.chainKey);
  }

  getCounter() {
    return this.messageCounter;
  }

  static deriveEncryptionParams(messageKey, nonce) {
    if (!messageKey || messageKey.length !== 32) {
      throw new Error('Invalid message key');
    }

    if (!nonce || nonce.length !== 16) {
      throw new Error('Invalid nonce');
    }
    const encParams = crypto.hkdfSync(
      'sha256',
      messageKey,
      nonce,
      'encryption',
      48
    );

    return {
      key: encParams.slice(0, 32),
      iv: encParams.slice(32, 48)
    };
  }

  static deriveAuthKey(messageKey, nonce) {
    return crypto.hkdfSync(
      'sha256',
      messageKey,
      nonce,
      'authentication',
      32
    );
  }

  encryptMessage(plaintext, additionalData = '') {
    if (typeof plaintext !== 'string' && !Buffer.isBuffer(plaintext)) {
      throw new Error('Invalid plaintext');
    }
    const { messageKey, counter } = this.deriveNextMessageKey();
    const nonce = crypto.randomBytes(16);
    const { key, iv } = ForwardSecrecyRatchet.deriveEncryptionParams(messageKey, nonce);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (additionalData) {
      cipher.setAAD(Buffer.from(additionalData));
    }

    const ciphertext = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
    const tag = cipher.getAuthTag();
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

  static decryptMessage(encryptedPacket, messageKey) {
    if (!encryptedPacket || !messageKey) {
      throw new Error('Invalid decryption parameters');
    }

    const { ciphertext, iv, nonce, tag, signature } = encryptedPacket;
    if (!ciphertext || !iv || !nonce || !tag || !signature) {
      throw new Error('Missing decryption packet fields');
    }
    const { key, iv: deriveIv } = ForwardSecrecyRatchet.deriveEncryptionParams(
      messageKey,
      Buffer.from(nonce, 'hex')
    );
    const authKey = ForwardSecrecyRatchet.deriveAuthKey(messageKey, Buffer.from(nonce, 'hex'));
    const expectedSignature = crypto
      .createHmac('sha256', authKey)
      .update(ciphertext + encryptedPacket.counter.toString())
      .digest('hex');

    if (signature !== expectedSignature) {
      throw new Error('Invalid signature - message tampering detected');
    }
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, deriveIv);
    decipher.setAuthTag(Buffer.from(tag, 'hex'));

    const plaintext = decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');

    return {
      plaintext,
      counter: encryptedPacket.counter,
      timestamp: encryptedPacket.timestamp
    };
  }

  getHistory(limit = 100) {
    return this.ratchetHistory.slice(-limit);
  }

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

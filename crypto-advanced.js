const crypto = require('crypto');

class CryptoAdvanced {

  static computeIdentityFingerprint(identityPublicKey) {
    const hash = crypto
      .createHash('sha256')
      .update(JSON.stringify(identityPublicKey))
      .digest('hex');
    return hash;
  }

  static generateSignedPrekey() {
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      signature: crypto
        .randomBytes(64)
        .toString('hex')
    };
  }

  static generateOneTimePrekeys(count) {
    const keys = [];
    for (let i = 0; i < count; i++) {
      keys.push({
        id: i,
        key: crypto.randomBytes(32).toString('hex'),
        used: false
      });
    }
    return keys;
  }

  static detectIdentityChange(participantId, newFingerprint, identityHistory) {
    if (!identityHistory.has(participantId)) {
      identityHistory.set(participantId, newFingerprint);
      return false;
    }

    const oldFingerprint = identityHistory.get(participantId);
    if (oldFingerprint !== newFingerprint) {
      identityHistory.set(participantId, newFingerprint);
      return true;
    }
    return false;
  }

  static deriveEmojis(fingerprint, count) {
    const emojiList = [
      'ALFA', 'BRAVO', 'CHARLIE', 'DELTA', 'ECHO', 'FOXTROT',
      'GOLF', 'HOTEL', 'INDIA', 'JULIET', 'KILO', 'LIMA',
      'MIKE', 'NOVEMBER', 'OSCAR', 'PAPA', 'QUEBEC', 'ROMEO',
      'SIERRA', 'TANGO', 'UNIFORM', 'VICTOR', 'WHISKEY', 'XRAY',
      'YANKEE', 'ZULU'
    ];

    const hash = crypto
      .createHash('sha256')
      .update(fingerprint)
      .digest();

    const emojis = [];
    for (let i = 0; i < count; i++) {
      const index = hash[i] % emojiList.length;
      emojis.push(emojiList[index]);
    }
    return emojis;
  }

  static generateECDHKeyPair() {
    return crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  }

  static computeSharedSecret(privateKey, publicKey) {
    const sharedSecret = crypto.diffieHellman({
      privateKey: crypto.createPrivateKey(privateKey),
      publicKey: crypto.createPublicKey(publicKey)
    });
    return sharedSecret;
  }

  static signData(privateKey, data) {
    const sign = crypto.createSign('sha256');
    sign.update(data);
    return sign.sign(privateKey, 'hex');
  }

  static verifySignature(publicKey, data, signature) {
    const verify = crypto.createVerify('sha256');
    verify.update(data);
    return verify.verify(publicKey, Buffer.from(signature, 'hex'));
  }

  static deriveKey(masterKey, salt, info) {
    return crypto
      .hkdf('sha256', masterKey, salt, info, 32);
  }

  static generateIV() {
    return crypto.randomBytes(12);
  }

  static encryptAES256GCM(plaintext, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return {
      ciphertext: encrypted,
      authTag: authTag.toString('hex'),
      iv: iv.toString('hex')
    };
  }

  static decryptAES256GCM(encrypted, key, iv, authTag) {
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      const decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
      return decrypted;
    } catch (error) {
      throw new Error('Decryption failed: ' + error.message);
    }
  }
}

module.exports = CryptoAdvanced;

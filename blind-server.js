'use strict';

const crypto = require('crypto');

class BlindEnvelopeStore {
  constructor() {
    this.store = new Map();
    this.TTL = 600000;
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }

  generateBucket() {
    return crypto.randomBytes(16).toString('hex');
  }

  put(bucket, envelopeId, encryptedBlob) {
    if (typeof bucket !== 'string' || bucket.length > 64) throw new Error('Invalid bucket');
    if (typeof envelopeId !== 'string' || envelopeId.length > 128) throw new Error('Invalid envelopeId');
    if (typeof encryptedBlob !== 'string' && !Buffer.isBuffer(encryptedBlob)) throw new Error('Invalid blob');
    const key = bucket + ':' + envelopeId;
    const paddedBlob = this.padBlob(encryptedBlob);
    this.store.set(key, {
      blob: paddedBlob,
      timestamp: Date.now(),
      size: typeof encryptedBlob === 'string' ? encryptedBlob.length : encryptedBlob.byteLength
    });
    return { stored: true, expiresIn: this.TTL };
  }

  get(bucket, envelopeId) {
    const key = bucket + ':' + envelopeId;
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this.TTL) {
      this.secureDelete(key);
      return null;
    }
    return { blob: this.unpadBlob(entry.blob, entry.size) };
  }

  remove(bucket, envelopeId) {
    const key = bucket + ':' + envelopeId;
    this.secureDelete(key);
  }

  padBlob(blob) {
    const data = typeof blob === 'string' ? Buffer.from(blob) : blob;
    const blockSize = 1024;
    const paddedSize = Math.ceil(data.length / blockSize) * blockSize;
    const padded = Buffer.alloc(paddedSize);
    data.copy(padded);
    crypto.randomFillSync(padded, data.length);
    return padded;
  }

  unpadBlob(paddedBlob, originalSize) {
    return paddedBlob.slice(0, originalSize).toString();
  }

  secureDelete(key) {
    const entry = this.store.get(key);
    if (entry && Buffer.isBuffer(entry.blob)) {
      crypto.randomFillSync(entry.blob);
    }
    this.store.delete(key);
  }

  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now - entry.timestamp > this.TTL) {
        this.secureDelete(key);
      }
    }
  }

  destroy() {
    for (const key of this.store.keys()) {
      this.secureDelete(key);
    }
    clearInterval(this.cleanupInterval);
  }
}

class MetadataStripper {
  strip(req) {
    const cleaned = {
      timestamp: Date.now(),
      requestId: crypto.randomBytes(16).toString('hex')
    };
    return cleaned;
  }

  middleware() {
    return (req, res, next) => {
      req.blindMeta = this.strip(req);
      req.headers['x-forwarded-for'] = undefined;
      req.headers['user-agent'] = undefined;
      req.headers['referer'] = undefined;
      req.headers['origin'] = undefined;
      next();
    };
  }
}

class SealedSender {
  constructor() {
    this.serverKeyPair = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
  }

  getServerPublicKey() {
    return this.serverKeyPair.publicKey;
  }

  seal(senderIdentity, recipientBucket, encryptedPayload) {
    const ephemeral = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    const sharedSecret = crypto.diffieHellman({
      privateKey: crypto.createPrivateKey({ key: ephemeral.privateKey, format: 'der', type: 'pkcs8' }),
      publicKey: crypto.createPublicKey({ key: this.serverKeyPair.publicKey, format: 'der', type: 'spki' })
    });
    const key = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(32, 0), Buffer.from('sealed-sender'), 32));
    const iv = crypto.randomBytes(12);
    const inner = JSON.stringify({
      sender: senderIdentity,
      bucket: recipientBucket,
      payload: encryptedPayload
    });
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(Buffer.from(inner)), cipher.final()]);
    return {
      ephemeralPub: ephemeral.publicKey.toString('base64'),
      ciphertext: ct.toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64')
    };
  }

  unseal(sealedMessage) {
    const ephPub = Buffer.from(sealedMessage.ephemeralPub, 'base64');
    const sharedSecret = crypto.diffieHellman({
      privateKey: crypto.createPrivateKey({ key: this.serverKeyPair.privateKey, format: 'der', type: 'pkcs8' }),
      publicKey: crypto.createPublicKey({ key: ephPub, format: 'der', type: 'spki' })
    });
    const key = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(32, 0), Buffer.from('sealed-sender'), 32));
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm', key,
      Buffer.from(sealedMessage.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(sealedMessage.tag, 'base64'));
    const pt = Buffer.concat([
      decipher.update(Buffer.from(sealedMessage.ciphertext, 'base64')),
      decipher.final()
    ]);
    return JSON.parse(pt.toString('utf8'));
  }
}

class UnlinkableDelivery {
  constructor(store) {
    this.store = store;
    this.noise = true;
  }

  async deliver(bucket, envelopeId, blob) {
    if (this.noise) {
      const delayMs = crypto.randomInt(50, 500);
      await new Promise(r => setTimeout(r, delayMs));
    }
    return this.store.put(bucket, envelopeId, blob);
  }

  async retrieve(bucket, envelopeId) {
    if (this.noise) {
      const delayMs = crypto.randomInt(50, 500);
      await new Promise(r => setTimeout(r, delayMs));
    }
    return this.store.get(bucket, envelopeId);
  }
}

module.exports = {
  BlindEnvelopeStore,
  MetadataStripper,
  SealedSender,
  UnlinkableDelivery
};

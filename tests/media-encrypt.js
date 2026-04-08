'use strict';

const crypto = require('crypto');

const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'image/heic', 'image/heif',
  'video/mp4', 'video/webm', 'video/quicktime', 'video/x-matroska'
]);

const MAX_MEDIA_SIZE_BYTES = 100 * 1024 * 1024;
const CHUNK_SIZE = 5 * 1024 * 1024;

function validateMedia(mediaBuffer, mimeType) {
  if (!Buffer.isBuffer(mediaBuffer) || mediaBuffer.length === 0) {
    throw new Error('Media buffer invalide ou vide');
  }
  if (mediaBuffer.length > MAX_MEDIA_SIZE_BYTES) {
    throw new Error(`Média trop volumineux (max ${MAX_MEDIA_SIZE_BYTES / 1024 / 1024} Mo)`);
  }
  if (typeof mimeType !== 'string' || !ALLOWED_MIME_TYPES.has(mimeType)) {
    throw new Error(`Type MIME non autorisé : ${mimeType}`);
  }
}

function generateMediaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

function deriveAESKey(sharedSecret, salt) {
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, Buffer.from('nexus-media-key'), 32));
}

function encryptMedia(mediaBuffer, aesKey) {
  if (!Buffer.isBuffer(aesKey) || aesKey.length !== 32) {
    throw new Error('Clé AES invalide (32 octets requis)');
  }

  const chunks = [];
  let offset = 0;

  while (offset < mediaBuffer.length) {
    const slice = mediaBuffer.slice(offset, offset + CHUNK_SIZE);
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(slice), cipher.final()]);
    const authTag = cipher.getAuthTag();

    chunks.push({
      index:      chunks.length,
      iv:         iv.toString('base64'),
      authTag:    authTag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      size:       slice.length
    });

    offset += CHUNK_SIZE;
  }

  return {
    chunks,
    totalSize:  mediaBuffer.length,
    chunkCount: chunks.length
  };
}

function decryptMedia(encryptedMedia, aesKey) {
  if (!Buffer.isBuffer(aesKey) || aesKey.length !== 32) {
    throw new Error('Clé AES invalide (32 octets requis)');
  }

  const parts = [];

  const sorted = [...encryptedMedia.chunks].sort((a, b) => a.index - b.index);

  for (const chunk of sorted) {
    const iv         = Buffer.from(chunk.iv,         'base64');
    const authTag    = Buffer.from(chunk.authTag,    'base64');
    const ciphertext = Buffer.from(chunk.ciphertext, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);

    try {
      parts.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
    } catch {
      throw new Error(`Échec de déchiffrement du chunk ${chunk.index} – données corrompues ou falsifiées`);
    }
  }

  return Buffer.concat(parts);
}

function senderEncryptMedia(mediaBuffer, mimeType, recipientPublicKeyPEM) {
  validateMedia(mediaBuffer, mimeType);

  const { publicKey: ephemeralPub, privateKey: ephemeralPriv } = generateMediaKeyPair();

  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(ephemeralPriv),
    publicKey:  crypto.createPublicKey(recipientPublicKeyPEM)
  });

  const salt       = crypto.randomBytes(32);
  const aesKey     = deriveAESKey(sharedSecret, salt);
  const encrypted  = encryptMedia(mediaBuffer, aesKey);

  const metaHmac = crypto.createHmac('sha256', aesKey)
    .update(JSON.stringify({ mimeType, totalSize: encrypted.totalSize, chunkCount: encrypted.chunkCount }))
    .digest('base64');

  return {
    envelope: {
      mimeType,
      salt:         salt.toString('base64'),
      ephemeralPub,
      encrypted,
      metaHmac
    }
  };
}

function recipientDecryptMedia(envelope, recipientPrivKeyPEM) {
  const { mimeType, salt, ephemeralPub, encrypted, metaHmac } = envelope;

  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(recipientPrivKeyPEM),
    publicKey:  crypto.createPublicKey(ephemeralPub)
  });

  const aesKey = deriveAESKey(sharedSecret, Buffer.from(salt, 'base64'));

  const expectedHmac = crypto.createHmac('sha256', aesKey)
    .update(JSON.stringify({ mimeType, totalSize: encrypted.totalSize, chunkCount: encrypted.chunkCount }))
    .digest('base64');

  if (!crypto.timingSafeEqual(Buffer.from(metaHmac, 'base64'), Buffer.from(expectedHmac, 'base64'))) {
    throw new Error('HMAC invalide – enveloppe corrompue ou falsifiée');
  }

  return decryptMedia(encrypted, aesKey);
}

module.exports = {
  ALLOWED_MIME_TYPES,
  MAX_MEDIA_SIZE_BYTES,
  generateMediaKeyPair,
  deriveAESKey,
  encryptMedia,
  decryptMedia,
  senderEncryptMedia,
  recipientDecryptMedia
};

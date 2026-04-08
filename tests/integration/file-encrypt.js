'use strict';

const crypto = require('crypto');

const ALLOWED_FILE_TYPES = new Set([
  'application/pdf',
  'application/zip', 'application/x-zip-compressed', 'application/x-7z-compressed',
  'application/x-rar-compressed', 'application/x-tar', 'application/gzip',
  'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/json', 'application/xml',
  'text/plain', 'text/csv', 'text/html', 'text/css', 'text/javascript',
  'application/octet-stream',
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
  'video/mp4', 'video/webm',
  'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm'
]);

const MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024;
const CHUNK_SIZE = 5 * 1024 * 1024;

function validateFile(fileBuffer, mimeType, fileName) {
  if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
    throw new Error('File buffer invalid or empty');
  }
  if (fileBuffer.length > MAX_FILE_SIZE_BYTES) {
    throw new Error('File exceeds maximum size of ' + (MAX_FILE_SIZE_BYTES / 1024 / 1024) + ' MB');
  }
  if (typeof mimeType !== 'string' || !ALLOWED_FILE_TYPES.has(mimeType)) {
    throw new Error('File type not allowed: ' + mimeType);
  }
  if (typeof fileName !== 'string' || fileName.length === 0 || fileName.length > 255) {
    throw new Error('Invalid file name');
  }
  const dangerous = /\.(exe|bat|cmd|com|scr|pif|msi|vbs|js|ws|wsf|ps1|sh)$/i;
  if (dangerous.test(fileName)) {
    throw new Error('Executable file types are blocked');
  }
}

function generateFileKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

function deriveFileAESKey(sharedSecret, salt) {
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, Buffer.from('nexus-file-key'), 32));
}

function encryptFile(fileBuffer, aesKey) {
  if (!Buffer.isBuffer(aesKey) || aesKey.length !== 32) {
    throw new Error('Invalid AES key (32 bytes required)');
  }
  const chunks = [];
  let offset = 0;
  while (offset < fileBuffer.length) {
    const slice = fileBuffer.slice(offset, offset + CHUNK_SIZE);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(slice), cipher.final()]);
    const authTag = cipher.getAuthTag();
    chunks.push({
      index: chunks.length,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      size: slice.length
    });
    offset += CHUNK_SIZE;
  }
  return { chunks, totalSize: fileBuffer.length, chunkCount: chunks.length };
}

function decryptFile(encryptedFile, aesKey) {
  if (!Buffer.isBuffer(aesKey) || aesKey.length !== 32) {
    throw new Error('Invalid AES key (32 bytes required)');
  }
  const parts = [];
  const sorted = [...encryptedFile.chunks].sort((a, b) => a.index - b.index);
  for (const chunk of sorted) {
    const iv = Buffer.from(chunk.iv, 'base64');
    const authTag = Buffer.from(chunk.authTag, 'base64');
    const ciphertext = Buffer.from(chunk.ciphertext, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);
    try {
      parts.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
    } catch {
      throw new Error('Decryption failed on chunk ' + chunk.index + ' - data corrupted or tampered');
    }
  }
  return Buffer.concat(parts);
}

function encryptFileName(fileName, aesKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(fileName, 'utf8')), cipher.final()]);
  return {
    encryptedName: ct.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64')
  };
}

function decryptFileName(encName, aesKey) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm', aesKey,
    Buffer.from(encName.iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(encName.tag, 'base64'));
  const pt = Buffer.concat([
    decipher.update(Buffer.from(encName.encryptedName, 'base64')),
    decipher.final()
  ]);
  return pt.toString('utf8');
}

function senderEncryptFile(fileBuffer, mimeType, fileName, recipientPublicKeyPEM) {
  validateFile(fileBuffer, mimeType, fileName);
  const { publicKey: ephemeralPub, privateKey: ephemeralPriv } = generateFileKeyPair();
  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(ephemeralPriv),
    publicKey: crypto.createPublicKey(recipientPublicKeyPEM)
  });
  const salt = crypto.randomBytes(32);
  const aesKey = deriveFileAESKey(sharedSecret, salt);
  const encrypted = encryptFile(fileBuffer, aesKey);
  const encName = encryptFileName(fileName, aesKey);
  const metaHmac = crypto.createHmac('sha256', aesKey)
    .update(JSON.stringify({
      mimeType,
      totalSize: encrypted.totalSize,
      chunkCount: encrypted.chunkCount,
      encryptedName: encName.encryptedName
    }))
    .digest('base64');
  return {
    envelope: {
      mimeType,
      salt: salt.toString('base64'),
      ephemeralPub,
      encrypted,
      encryptedFileName: encName,
      metaHmac
    }
  };
}

function recipientDecryptFile(envelope, recipientPrivKeyPEM) {
  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(recipientPrivKeyPEM),
    publicKey: crypto.createPublicKey(envelope.ephemeralPub)
  });
  const salt = Buffer.from(envelope.salt, 'base64');
  const aesKey = deriveFileAESKey(sharedSecret, salt);
  const expectedHmac = crypto.createHmac('sha256', aesKey)
    .update(JSON.stringify({
      mimeType: envelope.mimeType,
      totalSize: envelope.encrypted.totalSize,
      chunkCount: envelope.encrypted.chunkCount,
      encryptedName: envelope.encryptedFileName.encryptedName
    }))
    .digest();
  const actualHmac = Buffer.from(envelope.metaHmac, 'base64');
  if (!crypto.timingSafeEqual(expectedHmac, actualHmac)) {
    throw new Error('HMAC verification failed - envelope tampered');
  }
  const fileName = decryptFileName(envelope.encryptedFileName, aesKey);
  const fileBuffer = decryptFile(envelope.encrypted, aesKey);
  return { fileName, fileBuffer, mimeType: envelope.mimeType };
}

module.exports = {
  ALLOWED_FILE_TYPES,
  MAX_FILE_SIZE_BYTES,
  validateFile,
  generateFileKeyPair,
  deriveFileAESKey,
  encryptFile,
  decryptFile,
  encryptFileName,
  decryptFileName,
  senderEncryptFile,
  recipientDecryptFile
};

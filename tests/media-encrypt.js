/**
 * NEXUS SECURE - Module d'envoi de photos & vidéos chiffrées E2E
 * Chiffrement : AES-256-GCM + ECDH (prime256v1)
 * Les médias ne transitent JAMAIS en clair.
 */

'use strict';

const crypto = require('crypto');
const path = require('path');

// Types MIME autorisés (images + vidéos uniquement)
const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'image/heic', 'image/heif',
  'video/mp4', 'video/webm', 'video/quicktime', 'video/x-matroska'
]);

// Taille maximale d'un média : 100 Mo
const MAX_MEDIA_SIZE_BYTES = 100 * 1024 * 1024;

// Taille d'un chunk (5 Mo) – pour le chiffrement par morceaux
const CHUNK_SIZE = 5 * 1024 * 1024;

/**
 * Valide le type MIME et la taille du média avant tout chiffrement.
 * @param {Buffer} mediaBuffer  Contenu brut du fichier
 * @param {string} mimeType     Type MIME déclaré par l'expéditeur
 */
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

/**
 * Génère une paire de clés ECDH pour une session de transfert de média.
 * @returns {{ publicKey: string, privateKey: string }}  Clés PEM
 */
function generateMediaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

/**
 * Dérive une clé AES-256 depuis le secret ECDH partagé via HKDF-SHA256.
 * @param {Buffer} sharedSecret  Secret ECDH brut
 * @param {Buffer} salt          Sel aléatoire (32 octets recommandés)
 * @returns {Buffer}  Clé de 32 octets
 */
function deriveAESKey(sharedSecret, salt) {
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, Buffer.from('nexus-media-key'), 32));
}

/**
 * Chiffre un Buffer de média avec AES-256-GCM.
 * Chaque chunk a son propre IV pour éviter la réutilisation de nonce.
 * @param {Buffer} mediaBuffer
 * @param {Buffer} aesKey       Clé AES-256 (32 octets)
 * @returns {{ chunks: Array, totalSize: number, chunkCount: number }}
 */
function encryptMedia(mediaBuffer, aesKey) {
  if (!Buffer.isBuffer(aesKey) || aesKey.length !== 32) {
    throw new Error('Clé AES invalide (32 octets requis)');
  }

  const chunks = [];
  let offset = 0;

  while (offset < mediaBuffer.length) {
    const slice = mediaBuffer.slice(offset, offset + CHUNK_SIZE);
    const iv = crypto.randomBytes(12); // 96 bits – recommandé GCM

    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(slice), cipher.final()]);
    const authTag = cipher.getAuthTag(); // 128 bits

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

/**
 * Déchiffre les chunks d'un média et retourne le Buffer original.
 * @param {{ chunks: Array }} encryptedMedia  Résultat de encryptMedia()
 * @param {Buffer} aesKey
 * @returns {Buffer}  Contenu déchiffré
 */
function decryptMedia(encryptedMedia, aesKey) {
  if (!Buffer.isBuffer(aesKey) || aesKey.length !== 32) {
    throw new Error('Clé AES invalide (32 octets requis)');
  }

  const parts = [];

  // Traité dans l'ordre du champ index pour garantir l'intégrité
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

/**
 * Pipeline complet côté expéditeur :
 * 1. Validation du média
 * 2. ECDH éphémère → secret partagé
 * 3. Dérivation de la clé AES
 * 4. Chiffrement par chunks
 *
 * @param {Buffer} mediaBuffer
 * @param {string} mimeType
 * @param {string} recipientPublicKeyPEM  Clé publique ECDH du destinataire (PEM)
 * @returns {{ envelope: object, senderPublicKey: string }}
 *   envelope : tout ce qui est transmis au destinataire (aucune clé privée)
 */
function senderEncryptMedia(mediaBuffer, mimeType, recipientPublicKeyPEM) {
  validateMedia(mediaBuffer, mimeType);

  // Paire de clés éphémère (usage unique par envoi)
  const { publicKey: ephemeralPub, privateKey: ephemeralPriv } = generateMediaKeyPair();

  // Dérivation du secret partagé ECDH
  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(ephemeralPriv),
    publicKey:  crypto.createPublicKey(recipientPublicKeyPEM)
  });

  const salt       = crypto.randomBytes(32);
  const aesKey     = deriveAESKey(sharedSecret, salt);
  const encrypted  = encryptMedia(mediaBuffer, aesKey);

  // Signature HMAC sur les métadonnées pour garantir l'intégrité
  const metaHmac = crypto.createHmac('sha256', aesKey)
    .update(JSON.stringify({ mimeType, totalSize: encrypted.totalSize, chunkCount: encrypted.chunkCount }))
    .digest('base64');

  return {
    envelope: {
      mimeType,
      salt:         salt.toString('base64'),
      ephemeralPub,             // Le destinataire en a besoin pour reconstruire le secret
      encrypted,
      metaHmac
    },
    // La clé privée éphémère est détruite après l'appel (pas stockée dans l'enveloppe)
  };
}

/**
 * Pipeline complet côté destinataire :
 * 1. Reconstruction du secret partagé ECDH
 * 2. Dérivation de la clé AES
 * 3. Vérification HMAC
 * 4. Déchiffrement par chunks
 *
 * @param {object} envelope              Reçu de l'expéditeur
 * @param {string} recipientPrivKeyPEM   Clé privée ECDH du destinataire (PEM)
 * @returns {Buffer}  Buffer du média en clair (jamais stocké sur le serveur)
 */
function recipientDecryptMedia(envelope, recipientPrivKeyPEM) {
  const { mimeType, salt, ephemeralPub, encrypted, metaHmac } = envelope;

  // Reconstruction du secret partagé
  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(recipientPrivKeyPEM),
    publicKey:  crypto.createPublicKey(ephemeralPub)
  });

  const aesKey = deriveAESKey(sharedSecret, Buffer.from(salt, 'base64'));

  // Vérification de l'intégrité des métadonnées
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

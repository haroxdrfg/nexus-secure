#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const assert = require('assert');
const {
  generateMediaKeyPair,
  deriveAESKey,
  encryptMedia,
  decryptMedia,
  senderEncryptMedia,
  recipientDecryptMedia,
  ALLOWED_MIME_TYPES,
  MAX_MEDIA_SIZE_BYTES
} = require('./media-encrypt');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  [OK] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failed++;
  }
}

console.log('\n=== NEXUS SECURE – Tests media chiffres ===\n');

console.log('1. Generation de paires de cles ECDH');

test('generateMediaKeyPair() retourne publicKey et privateKey PEM', () => {
  const kp = generateMediaKeyPair();
  assert.ok(kp.publicKey.includes('PUBLIC KEY'),  'Clé publique PEM attendue');
  assert.ok(kp.privateKey.includes('PRIVATE KEY'), 'Clé privée PEM attendue');
});

test('Deux générations produisent des clés distinctes', () => {
  const kp1 = generateMediaKeyPair();
  const kp2 = generateMediaKeyPair();
  assert.notStrictEqual(kp1.publicKey, kp2.publicKey);
  assert.notStrictEqual(kp1.privateKey, kp2.privateKey);
});

console.log('\n2. Derivation de cle AES-256 via HKDF');

test('deriveAESKey() produit un Buffer de 32 octets', () => {
  const secret = crypto.randomBytes(32);
  const salt   = crypto.randomBytes(32);
  const key    = deriveAESKey(secret, salt);
  assert.ok(Buffer.isBuffer(key), 'Doit être un Buffer');
  assert.strictEqual(key.length, 32, 'Doit faire 32 octets');
});

test('Même secret + sel = même clé (déterministe)', () => {
  const secret = crypto.randomBytes(32);
  const salt   = crypto.randomBytes(32);
  const k1 = deriveAESKey(secret, salt);
  const k2 = deriveAESKey(secret, salt);
  assert.ok(k1.equals(k2), 'Les clés doivent être identiques');
});

test('Sel différent = clé différente', () => {
  const secret = crypto.randomBytes(32);
  const k1 = deriveAESKey(secret, crypto.randomBytes(32));
  const k2 = deriveAESKey(secret, crypto.randomBytes(32));
  assert.ok(!k1.equals(k2), 'Les clés doivent différer');
});

console.log('\n3. Chiffrement AES-256-GCM par chunks');

test('Chiffrer puis déchiffrer une image simulée (JPEG ~50 Ko)', () => {
  const fakeImage  = crypto.randomBytes(50 * 1024);
  const aesKey     = crypto.randomBytes(32);
  const encrypted  = encryptMedia(fakeImage, aesKey);
  const decrypted  = decryptMedia(encrypted, aesKey);
  assert.ok(fakeImage.equals(decrypted), 'Le contenu déchiffré doit être identique');
});

test('Chiffrer puis déchiffrer une vidéo simulée (6 Mo, multi-chunk)', () => {
  const fakeVideo  = crypto.randomBytes(6 * 1024 * 1024);
  const aesKey     = crypto.randomBytes(32);
  const encrypted  = encryptMedia(fakeVideo, aesKey);
  assert.strictEqual(encrypted.chunkCount, 2, 'Doit produire 2 chunks pour 6 Mo');
  const decrypted  = decryptMedia(encrypted, aesKey);
  assert.ok(fakeVideo.equals(decrypted), 'Le contenu déchiffré doit être identique');
});

test('Le ciphertext est différent du plaintext', () => {
  const data    = Buffer.from('Ceci est une photo secrète');
  const aesKey  = crypto.randomBytes(32);
  const { chunks } = encryptMedia(data, aesKey);
  const ct = Buffer.from(chunks[0].ciphertext, 'base64');
  assert.ok(!data.equals(ct), 'Le ciphertext ne doit pas être en clair');
});

test('Mauvaise clé AES : déchiffrement doit échouer', () => {
  const data       = crypto.randomBytes(1024);
  const aesKey     = crypto.randomBytes(32);
  const wrongKey   = crypto.randomBytes(32);
  const encrypted  = encryptMedia(data, aesKey);
  assert.throws(() => decryptMedia(encrypted, wrongKey), /Échec de déchiffrement/);
});

test('Chunk falsifié : déchiffrement doit échouer (intégrité GCM)', () => {
  const data      = crypto.randomBytes(1024);
  const aesKey    = crypto.randomBytes(32);
  const encrypted = encryptMedia(data, aesKey);
  encrypted.chunks[0].authTag = crypto.randomBytes(16).toString('base64');
  assert.throws(() => decryptMedia(encrypted, aesKey));
});

console.log('\n4. Pipeline complet expediteur / destinataire');

test('Envoi photo chiffrée (image/jpeg)', () => {
  const { publicKey: recipPub, privateKey: recipPriv } = generateMediaKeyPair();
  const fakeJpeg = crypto.randomBytes(30 * 1024);

  const { envelope } = senderEncryptMedia(fakeJpeg, 'image/jpeg', recipPub);
  assert.ok(envelope.encrypted.chunks.length > 0, 'Des chunks chiffrés doivent exister');
  assert.ok(!envelope.recipientPrivKey, 'La clé privée ne doit pas figurer dans l\'enveloppe');

  const decrypted = recipientDecryptMedia(envelope, recipPriv);
  assert.ok(fakeJpeg.equals(decrypted), 'Contenu identique après déchiffrement');
});

test('Envoi vidéo chiffrée (video/mp4)', () => {
  const { publicKey: recipPub, privateKey: recipPriv } = generateMediaKeyPair();
  const fakeMp4 = crypto.randomBytes(8 * 1024 * 1024);

  const { envelope } = senderEncryptMedia(fakeMp4, 'video/mp4', recipPub);
  assert.ok(envelope.encrypted.chunkCount >= 2, 'Plusieurs chunks pour 8 Mo');

  const decrypted = recipientDecryptMedia(envelope, recipPriv);
  assert.ok(fakeMp4.equals(decrypted), 'Contenu identique après déchiffrement');
});

test('Type MIME non autorisé : rejet avant chiffrement', () => {
  const { publicKey } = generateMediaKeyPair();
  const buf = crypto.randomBytes(1024);
  assert.throws(() => senderEncryptMedia(buf, 'application/exe', publicKey), /Type MIME non autorisé/);
});

test('Média vide : rejet avant chiffrement', () => {
  const { publicKey } = generateMediaKeyPair();
  assert.throws(() => senderEncryptMedia(Buffer.alloc(0), 'image/png', publicKey), /invalide ou vide/);
});

test('HMAC falsifié : déchiffrement destinataire doit échouer', () => {
  const { publicKey: recipPub, privateKey: recipPriv } = generateMediaKeyPair();
  const fakeImg = crypto.randomBytes(2048);

  const { envelope } = senderEncryptMedia(fakeImg, 'image/png', recipPub);
  envelope.metaHmac = crypto.randomBytes(32).toString('base64');
  assert.throws(() => recipientDecryptMedia(envelope, recipPriv), /HMAC invalide/);
});

test('Cle privee d\'un tiers : dechiffrement doit echouer', () => {
  const { publicKey: recipPub, privateKey: recipPriv } = generateMediaKeyPair();
  const { privateKey: thirdPartyPriv } = generateMediaKeyPair();
  const fakeImg = crypto.randomBytes(2048);

  const { envelope } = senderEncryptMedia(fakeImg, 'image/webp', recipPub);
  assert.throws(() => recipientDecryptMedia(envelope, thirdPartyPriv));
});

console.log('\n5. Types MIME autorises');

const expectedTypes = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'image/heic', 'image/heif',
  'video/mp4', 'video/webm', 'video/quicktime', 'video/x-matroska'
];

test('Tous les types attendus sont présents', () => {
  for (const t of expectedTypes) {
    assert.ok(ALLOWED_MIME_TYPES.has(t), `Type manquant : ${t}`);
  }
});

test('Types dangereux sont absents', () => {
  const dangerous = ['application/x-executable', 'text/html', 'application/javascript'];
  for (const t of dangerous) {
    assert.ok(!ALLOWED_MIME_TYPES.has(t), `Type dangereux présent : ${t}`);
  }
});

console.log('\n6. Limite de taille');

test('MAX_MEDIA_SIZE_BYTES vaut 100 Mo', () => {
  assert.strictEqual(MAX_MEDIA_SIZE_BYTES, 100 * 1024 * 1024);
});

test('Media depassant 100 Mo : rejet', () => {
  const { publicKey } = generateMediaKeyPair();
  const oversized = Buffer.alloc(MAX_MEDIA_SIZE_BYTES + 1);
  assert.throws(() => senderEncryptMedia(oversized, 'image/jpeg', publicKey), /trop volumineux/);
});

console.log(`\n=== Resultat : ${passed} reussi(s), ${failed} echoue(s) ===\n`);

if (failed > 0) process.exit(1);

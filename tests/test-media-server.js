#!/usr/bin/env node
'use strict';

const https = require('https');
const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');
const {
  generateMediaKeyPair,
  senderEncryptMedia,
  recipientDecryptMedia
} = require('./media-encrypt');

const ROOT = path.join(__dirname, '..');
const BASE = 'https://localhost:3000';

let passed = 0;
let failed = 0;
let serverProcess = null;

function request(method, endpoint, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: endpoint,
      method,
      rejectUnauthorized: false,
      headers: {
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {})
      }
    };

    const req = https.request(options, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(raw) });
        } catch {
          resolve({ status: res.statusCode, body: raw });
        }
      });
    });

    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function test(name, fn) {
  try {
    await fn();
    console.log(`  [OK] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failed++;
  }
}

function waitReady(retries = 20, delay = 500) {
  return new Promise((resolve, reject) => {
    const attempt = (n) => {
      const req = https.request(
        { hostname: 'localhost', port: 3000, path: '/api/security/status', method: 'GET', rejectUnauthorized: false },
        (res) => { res.resume(); resolve(); }
      );
      req.on('error', () => {
        if (n <= 0) return reject(new Error('Serveur non disponible'));
        setTimeout(() => attempt(n - 1), delay);
      });
      req.end();
    };
    attempt(retries);
  });
}

function startServer() {
  return new Promise((resolve, reject) => {
    serverProcess = spawn(process.execPath, ['server.js'], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '0' }
    });

    serverProcess.stderr.on('data', () => {});
    serverProcess.stdout.on('data', () => {});
    serverProcess.on('error', reject);

    waitReady().then(resolve).catch(reject);
  });
}

function stopServer() {
  if (serverProcess) {
    serverProcess.kill('SIGTERM');
    serverProcess = null;
  }
}

async function runTests() {
  console.log('\n=== NEXUS SECURE - Tests media serveur ===\n');
  console.log('Demarrage du serveur...');

  try {
    await startServer();
    console.log('Serveur pret.\n');
  } catch (err) {
    console.error('[FAIL] Impossible de demarrer le serveur:', err.message);
    process.exit(1);
  }

  const { publicKey: bobPub, privateKey: bobPriv } = generateMediaKeyPair();

  console.log('1. POST /api/media/store - envoi photo chiffree');

  let storedMediaId;

  await test('Stocker une enveloppe image/jpeg chiffree', async () => {
    const fakeJpeg = crypto.randomBytes(30 * 1024);
    const { envelope } = senderEncryptMedia(fakeJpeg, 'image/jpeg', bobPub);
    storedMediaId = crypto.randomUUID();

    const res = await request('POST', '/api/media/store', { mediaId: storedMediaId, envelope });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body)}`);
    if (!res.body.success) throw new Error('success=false');
    if (res.body.mediaId !== storedMediaId) throw new Error('mediaId mismatch');
  });

  await test('Stocker une enveloppe video/mp4 chiffree', async () => {
    const fakeMp4 = crypto.randomBytes(2 * 1024 * 1024);
    const { envelope } = senderEncryptMedia(fakeMp4, 'video/mp4', bobPub);
    const id = crypto.randomUUID();

    const res = await request('POST', '/api/media/store', { mediaId: id, envelope });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.body.success) throw new Error('success=false');
  });

  await test('Rejeter un type MIME non autorise (application/exe)', async () => {
    const buf = crypto.randomBytes(1024);
    const { publicKey } = generateMediaKeyPair();
    const { envelope } = senderEncryptMedia(buf, 'image/png', publicKey);
    envelope.mimeType = 'application/exe';

    const res = await request('POST', '/api/media/store', { mediaId: crypto.randomUUID(), envelope });
    if (res.status !== 400) throw new Error(`Attendu 400, recu ${res.status}`);
  });

  await test('Rejeter une enveloppe sans mediaId', async () => {
    const res = await request('POST', '/api/media/store', { envelope: { mimeType: 'image/jpeg' } });
    if (res.status !== 400) throw new Error(`Attendu 400, recu ${res.status}`);
  });

  await test('Rejeter une enveloppe incomplete (champs manquants)', async () => {
    const res = await request('POST', '/api/media/store', {
      mediaId: crypto.randomUUID(),
      envelope: { mimeType: 'image/jpeg', salt: 'abc' }
    });
    if (res.status !== 400) throw new Error(`Attendu 400, recu ${res.status}`);
  });

  console.log('\n2. GET /api/media/retrieve/:mediaId - recuperation et dechiffrement');

  await test('Recuperer et dechiffrer une photo stockee', async () => {
    const fakeJpeg = crypto.randomBytes(20 * 1024);
    const { envelope } = senderEncryptMedia(fakeJpeg, 'image/jpeg', bobPub);
    const id = crypto.randomUUID();

    await request('POST', '/api/media/store', { mediaId: id, envelope });
    const res = await request('GET', `/api/media/retrieve/${id}`);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.body.envelope) throw new Error('Enveloppe absente de la reponse');

    const decrypted = recipientDecryptMedia(res.body.envelope, bobPriv);
    if (!fakeJpeg.equals(decrypted)) throw new Error('Contenu dechiffre different de loriginal');
  });

  await test('Recuperer une enveloppe video/webm et verifier integrite', async () => {
    const fakeWebm = crypto.randomBytes(512 * 1024);
    const { envelope } = senderEncryptMedia(fakeWebm, 'video/webm', bobPub);
    const id = crypto.randomUUID();

    await request('POST', '/api/media/store', { mediaId: id, envelope });
    const res = await request('GET', `/api/media/retrieve/${id}`);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);

    const decrypted = recipientDecryptMedia(res.body.envelope, bobPriv);
    if (!fakeWebm.equals(decrypted)) throw new Error('Contenu altere');
  });

  await test('Media inexistant : retourner 404', async () => {
    const res = await request('GET', `/api/media/retrieve/${crypto.randomUUID()}`);
    if (res.status !== 404) throw new Error(`Attendu 404, recu ${res.status}`);
  });

  await test('Enveloppe transmise sans cle privee (serveur aveugle)', async () => {
    const fakeImg = crypto.randomBytes(4 * 1024);
    const { envelope } = senderEncryptMedia(fakeImg, 'image/png', bobPub);
    const id = crypto.randomUUID();

    await request('POST', '/api/media/store', { mediaId: id, envelope });
    const res = await request('GET', `/api/media/retrieve/${id}`);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);

    const env = res.body.envelope;
    if (env.recipientPrivKey) throw new Error('Cle privee presente dans la reponse serveur');
    if (!env.ephemeralPub) throw new Error('ephemeralPub manquant');
    if (!env.salt) throw new Error('salt manquant');
  });

  console.log('\n3. DELETE /api/media/:mediaId - suppression');

  await test('Supprimer un media stocke', async () => {
    const { envelope } = senderEncryptMedia(crypto.randomBytes(1024), 'image/jpeg', bobPub);
    const id = crypto.randomUUID();

    await request('POST', '/api/media/store', { mediaId: id, envelope });
    const del = await request('DELETE', `/api/media/${id}`);
    if (del.status !== 200) throw new Error(`HTTP ${del.status}`);

    const get = await request('GET', `/api/media/retrieve/${id}`);
    if (get.status !== 404) throw new Error('Media encore accessible apres suppression');
  });

  console.log('\n=== Resultat : ' + passed + ' reussi(s), ' + failed + ' echoue(s) ===\n');

  stopServer();
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('[ERREUR FATALE]', err.message);
  stopServer();
  process.exit(1);
});

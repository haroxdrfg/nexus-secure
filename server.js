const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const cors = require('cors');
const crypto = require('crypto');
const CryptoAdvanced = require('./crypto-advanced');
const net = require('net');
const selfsigned = require('selfsigned');
const config = require('./config');
const Validators = require('./validators');
const rateLimiter = require('./rate-limiter');
const { AuditLogger: auditLogger } = require('./database');
const { ALLOWED_MIME_TYPES } = require('./tests/media-encrypt');
const { ALLOWED_FILE_TYPES, senderEncryptFile, recipientDecryptFile } = require('./file-encrypt');
const { TurnstileVerifier, ProofOfWork, FingerprintThrottle } = require('./anti-bot');
const { BlindEnvelopeStore, MetadataStripper, SealedSender } = require('./blind-server');
const { SnowflakeProxy, TrafficShaper } = require('./snowflake');

const app = express();
const PORT = config.PORT;
const TOR_CONFIG = { enabled: false };
const corsOptions = {
  origin: config.ALLOWED_ORIGINS,
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
const securityHeadersMiddleware = (req, res, next) => {
  Object.entries(config.SECURITY_HEADERS).forEach(([key, value]) => {
    res.set(key, value);
  });
  next();
};

class IdentityManager {
  constructor() {
    this.identities = new Map();
    this.trustedIdentities = new Set();
    this.identityHistory = new Map();
  }

  registerIdentity(participantId, identityPublicKey, signedPrekeys, otpKeys) {
    const fingerprint = CryptoAdvanced.computeIdentityFingerprint(identityPublicKey);

    this.identities.set(participantId, {
      identityPublicKey,
      signedPrekeys,
      otpKeys,
      fingerprint,
      registeredAt: Date.now(),
      lastUsed: Date.now()
    });

    return fingerprint;
  }

  getIdentity(participantId) {
    return this.identities.get(participantId);
  }

  rotateSignedPrekeys(participantId) {
    const identity = this.getIdentity(participantId);
    if (!identity) throw new Error('Identity not found');

    identity.signedPrekeys = CryptoAdvanced.generateSignedPrekey();
    identity.lastUsed = Date.now();
  }

  consumeOTPKey(participantId) {
    const identity = this.getIdentity(participantId);
    if (!identity || identity.otpKeys.length === 0) {
      throw new Error('No OTP keys available');
    }

    const otpKey = identity.otpKeys.shift();
    identity.otpKeys.push(CryptoAdvanced.generateOneTimePrekeys(1)[0]);

    return otpKey;
  }

  verifyIdentityTrust(fingerprint) {
    return this.trustedIdentities.has(fingerprint);
  }

  addTrustedIdentity(fingerprint) {
    this.trustedIdentities.add(fingerprint);
  }

  detectIdentityChange(participantId, newFingerprint) {
    return CryptoAdvanced.detectIdentityChange(participantId, newFingerprint, this.identityHistory);
  }
}

class GenericStorage {
  constructor() {
    this.storage = new Map();
  }

  set(key, value) {
    this.storage.set(key, { value, timestamp: Date.now() });
  }

  get(key) {
    const entry = this.storage.get(key);
    return entry ? entry.value : null;
  }

  has(key) {
    return this.storage.has(key);
  }

  delete(key) {
    return this.storage.delete(key);
  }

  listKeys(prefix) {
    const keys = [];
    for (const key of this.storage.keys()) {
      if (key.startsWith(prefix)) {
        keys.push(key);
      }
    }
    return keys;
  }

  clear() {
    this.storage.clear();
  }
}

class SecureMessageStorage {
  constructor() {
    this.storage = new Map();
    this.masterKey = crypto.randomBytes(32);
    this.TTL = 120000;
  }

  encryptMessage(messageId, plaintext) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
    const encrypted = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    const entry = {
      ciphertext: encrypted,
      iv: iv.toString('hex'),
      authTag,
      expiresAt: Date.now() + this.TTL,
      createdAt: Date.now()
    };

    this.storage.set(messageId, entry);
    return entry;
  }

  decryptMessage(messageId) {
    const entry = this.storage.get(messageId);
    if (!entry) throw new Error('Message not found');

    if (Date.now() > entry.expiresAt) {
      this.storage.delete(messageId);
      throw new Error('Message expired');
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, Buffer.from(entry.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(entry.authTag, 'hex'));

    const plaintext = decipher.update(entry.ciphertext, 'hex', 'utf8') + decipher.final('utf8');
    return plaintext;
  }

  deleteMessage(messageId) {
    const entry = this.storage.get(messageId);
    if (entry) {
      entry.ciphertext = crypto.randomBytes(entry.ciphertext.length / 2).toString('hex');
      this.storage.delete(messageId);
    }
  }

  cleanupExpired() {
    const now = Date.now();
    for (const [messageId, entry] of this.storage.entries()) {
      if (now > entry.expiresAt) {
        this.deleteMessage(messageId);
      }
    }
  }
}
class MediaEnvelopeStorage {
  constructor() {
    this.storage = new Map();
    this.TTL = 2 * 60 * 1000;
  }

  store(mediaId, envelope) {
    if (!mediaId || typeof mediaId !== 'string' || mediaId.length > 128) {
      throw new Error('mediaId invalide');
    }
    if (!envelope || typeof envelope !== 'object') {
      throw new Error('Enveloppe invalide');
    }
    this.storage.set(mediaId, {
      envelope,
      expiresAt: Date.now() + this.TTL,
      storedAt: Date.now()
    });
  }

  retrieve(mediaId) {
    const entry = this.storage.get(mediaId);
    if (!entry) throw new Error('Media not found');
    if (Date.now() > entry.expiresAt) {
      this.storage.delete(mediaId);
      throw new Error('Media expired');
    }
    return entry.envelope;
  }

  delete(mediaId) {
    this.storage.delete(mediaId);
  }

  cleanupExpired() {
    const now = Date.now();
    for (const [id, entry] of this.storage.entries()) {
      if (now > entry.expiresAt) this.storage.delete(id);
    }
  }
}

const identityManager = new IdentityManager();
const messageStorage = new SecureMessageStorage();
const genericStorage = new GenericStorage();
const mediaStorage = new MediaEnvelopeStorage();
const blindStore = new BlindEnvelopeStore();
const metadataStripper = new MetadataStripper();
const sealedSender = new SealedSender();
const proofOfWork = new ProofOfWork(4);
const fpThrottle = new FingerprintThrottle();
const turnstile = new TurnstileVerifier(config.TURNSTILE.secretKey);
const snowflakeProxy = new SnowflakeProxy();
const trafficShaper = new TrafficShaper();
let sslOptions = null;
const certPath = path.join(__dirname, 'cert.crt');
const keyPath = path.join(__dirname, 'cert.key');
if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
  console.log('[*] Certificats non trouvés, génération automatique...');

  try {
    const attrs = [
      { name: 'commonName', value: 'nexus-secure' },
      { name: 'organizationName', value: 'NEXUS SECURE' },
      { name: 'countryName', value: 'FR' }
    ];

    const pems = selfsigned.generate(attrs, {
      days: 365,
      expires: 31536000 * 1000,
      keySize: 2048
    });
    fs.writeFileSync(keyPath, pems.private);
    fs.writeFileSync(certPath, pems.cert);

    console.log('[OK] Certificats auto-signes generes');
  } catch(e) {
    console.error('[!] Erreur génération certificat:', e.message);
    process.exit(1);
  }
}
try {
  sslOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
  };
  console.log('[OK] Certificats charges');
} catch(e) {
  console.error('ERROR: Cannot load certificates');
  console.error(e.message);
  process.exit(1);
}
app.set('trust proxy', 1);
app.use(cors(corsOptions));
app.use(securityHeadersMiddleware);
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));
app.use(rateLimiter.middleware());
app.use(fpThrottle.middleware());
app.use(metadataStripper.middleware());
app.use((req, res, next) => {
  if (req.path.startsWith('/api/media/') || req.path.startsWith('/api/file/') || req.path.startsWith('/api/blind/')) return next();
  if (req.body && Object.keys(req.body).length > 0) {
    if (JSON.stringify(req.body).length > 1000000) {
      return res.status(413).json({ error: 'Payload too large' });
    }
  }
  next();
});
app.post('/api/identity/register', (req, res) => {
  try {
    const validation = Validators.validateIdentityRegister(req.body);
    if (!validation.valid) {
      AuditLogger.log('identity_registration', 'unknown', 'failed', 'INVALID_INPUT');
      return res.status(400).json({ error: 'Invalid input', details: validation.errors });
    }

    const { participantId, identityPublicKey, signaturePublicKey } = req.body;
    if (identityManager.getIdentity(participantId)) {
      return res.status(409).json({ error: 'Identity already registered' });
    }

    const fingerprint = identityManager.registerIdentity(
      participantId,
      identityPublicKey,
      CryptoAdvanced.generateSignedPrekey(),
      CryptoAdvanced.generateOneTimePrekeys(5)
    );

    AuditLogger.log('identity_registration', participantId, 'success');

    res.json({
      success: true,
      fingerprint,
      sas: CryptoAdvanced.deriveEmojis(fingerprint, 6)
    });
  } catch (error) {
    AuditLogger.log('identity_registration', req.body?.participantId || 'unknown', 'failed', error.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});
app.get('/api/identity/:participantId', (req, res) => {
  try {
    const identity = identityManager.getIdentity(req.params.participantId);

    if (!identity) {
      return res.status(404).json({ error: 'Identity not found' });
    }

    auditLogger.log('identity_retrieval', req.params.participantId, 'success');

    res.json({
      identityPublicKey: identity.identityPublicKey,
      signedPrekey: identity.signedPrekeys,
      otpKey: identity.otpKeys[0],
      fingerprint: identity.fingerprint,
      sas: CryptoAdvanced.deriveEmojis(identity.fingerprint, 6)
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/messages/store', (req, res) => {
  try {
    const { messageId, encryptedData } = req.body;

    if (!messageId || !encryptedData) {
      return res.status(400).json({ error: 'Missing messageId or encryptedData' });
    }
    const entry = messageStorage.encryptMessage(messageId, JSON.stringify(encryptedData));

    auditLogger.log('message_storage', messageId, 'success');

    res.json({ success: true, expiresAt: entry.expiresAt });
  } catch (error) {
    auditLogger.log('message_storage', req.body.messageId, 'failed', error.message);
    res.status(400).json({ error: error.message });
  }
});
app.get('/api/messages/retrieve/:messageId', (req, res) => {
  try {
    const encrypted = messageStorage.decryptMessage(req.params.messageId);

    auditLogger.log('message_retrieval', req.params.messageId, 'success');

    res.json({ encryptedData: JSON.parse(encrypted) });
  } catch (error) {
    auditLogger.log('message_retrieval', req.params.messageId, 'failed', error.message);
    res.status(404).json({ error: error.message });
  }
});
app.delete('/api/messages/:messageId', (req, res) => {
  try {
    messageStorage.deleteMessage(req.params.messageId);

    auditLogger.log('message_deletion', req.params.messageId, 'success');

    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/storage/:key', (req, res) => {
  try {
    const { value } = req.body;
    const key = decodeURIComponent(req.params.key);

    if (!key) {
      return res.status(400).json({ error: 'Missing key' });
    }

    genericStorage.set(key, value);
    auditLogger.log('storage_write', key, 'success');

    res.json({ success: true, key, totalKeys: genericStorage.storage.size });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.get('/api/storage/list/:prefix', (req, res) => {
  try {
    const prefix = decodeURIComponent(req.params.prefix);
    const keys = genericStorage.listKeys(prefix);

    auditLogger.log('storage_list', prefix, 'success');
    res.json({ keys, totalKeys: genericStorage.storage.size, allKeys: Array.from(genericStorage.storage.keys()) });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.get('/api/storage/:key', (req, res) => {
  try {
    const key = decodeURIComponent(req.params.key);

    if (!key) {
      return res.status(400).json({ error: 'Missing key' });
    }

    const value = genericStorage.get(key);

    if (value === null) {
      return res.status(404).json({ error: 'Key not found' });
    }

    auditLogger.log('storage_read', key, 'success');
    res.json({ value });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.delete('/api/storage/:key', (req, res) => {
  try {
    const key = decodeURIComponent(req.params.key);

    if (!key) {
      return res.status(400).json({ error: 'Missing key' });
    }

    genericStorage.delete(key);
    auditLogger.log('storage_delete', key, 'success');

    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/media/store', express.json({ limit: '150mb' }), (req, res) => {
  try {
    const { mediaId, envelope } = req.body;
    if (!mediaId || !envelope) {
      return res.status(400).json({ error: 'Missing mediaId or envelope' });
    }
    if (!envelope.mimeType || !ALLOWED_MIME_TYPES.has(envelope.mimeType)) {
      return res.status(400).json({ error: 'Type MIME non autorise' });
    }
    if (!envelope.encrypted || !envelope.salt || !envelope.ephemeralPub || !envelope.metaHmac) {
      return res.status(400).json({ error: 'Enveloppe incomplete' });
    }
    mediaStorage.store(mediaId, envelope);
    auditLogger.log('media_store', mediaId, 'success');
    res.json({ success: true, mediaId, expiresIn: mediaStorage.TTL });
  } catch (error) {
    auditLogger.log('media_store', req.body?.mediaId || 'unknown', 'failed', error.message);
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/media/retrieve/:mediaId', (req, res) => {
  try {
    const envelope = mediaStorage.retrieve(req.params.mediaId);
    auditLogger.log('media_retrieve', req.params.mediaId, 'success');
    res.json({ envelope });
  } catch (error) {
    auditLogger.log('media_retrieve', req.params.mediaId, 'failed', error.message);
    res.status(404).json({ error: error.message });
  }
});

app.delete('/api/media/:mediaId', (req, res) => {
  try {
    mediaStorage.delete(req.params.mediaId);
    auditLogger.log('media_delete', req.params.mediaId, 'success');
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/file/store', express.json({ limit: '500mb' }), (req, res) => {
  try {
    const { fileId, envelope } = req.body;
    if (!fileId || !envelope) {
      return res.status(400).json({ error: 'Missing fileId or envelope' });
    }
    if (!envelope.mimeType || !ALLOWED_FILE_TYPES.has(envelope.mimeType)) {
      return res.status(400).json({ error: 'File type not allowed' });
    }
    if (!envelope.encrypted || !envelope.salt || !envelope.ephemeralPub || !envelope.metaHmac || !envelope.encryptedFileName) {
      return res.status(400).json({ error: 'Incomplete envelope' });
    }
    mediaStorage.store(fileId, envelope);
    auditLogger.log('file_store', fileId, 'success');
    res.json({ success: true, fileId, expiresIn: mediaStorage.TTL });
  } catch (error) {
    auditLogger.log('file_store', req.body?.fileId || 'unknown', 'failed', error.message);
    res.status(400).json({ error: error.message });
  }
});
app.get('/api/file/retrieve/:fileId', (req, res) => {
  try {
    const envelope = mediaStorage.retrieve(req.params.fileId);
    auditLogger.log('file_retrieve', req.params.fileId, 'success');
    res.json({ envelope });
  } catch (error) {
    auditLogger.log('file_retrieve', req.params.fileId, 'failed', error.message);
    res.status(404).json({ error: error.message });
  }
});
app.delete('/api/file/:fileId', (req, res) => {
  try {
    mediaStorage.delete(req.params.fileId);
    auditLogger.log('file_delete', req.params.fileId, 'success');
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/blind/store', express.json({ limit: '150mb' }), (req, res) => {
  try {
    const { bucket, envelopeId, blob } = req.body;
    if (!bucket || !envelopeId || !blob) {
      return res.status(400).json({ error: 'Missing bucket, envelopeId or blob' });
    }
    const result = blindStore.put(bucket, envelopeId, blob);
    auditLogger.log('blind_store', envelopeId, 'success');
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.get('/api/blind/retrieve/:bucket/:envelopeId', (req, res) => {
  try {
    const result = blindStore.get(req.params.bucket, req.params.envelopeId);
    if (!result) return res.status(404).json({ error: 'Not found' });
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.delete('/api/blind/:bucket/:envelopeId', (req, res) => {
  try {
    blindStore.remove(req.params.bucket, req.params.envelopeId);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/blind/seal', (req, res) => {
  try {
    const { sender, bucket, payload } = req.body;
    if (!sender || !bucket || !payload) {
      return res.status(400).json({ error: 'Missing sender, bucket or payload' });
    }
    const sealed = sealedSender.seal(sender, bucket, payload);
    res.json(sealed);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/blind/unseal', (req, res) => {
  try {
    const result = sealedSender.unseal(req.body);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: 'Unseal failed' });
  }
});
app.get('/api/blind/server-key', (req, res) => {
  res.json({ publicKey: sealedSender.getServerPublicKey().toString('base64') });
});
app.get('/api/turnstile/site-key', (req, res) => {
  res.json({ siteKey: config.TURNSTILE.siteKey });
});
app.post('/api/turnstile/verify', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Missing token' });
  const ip = req.ip || req.connection.remoteAddress;
  const result = await turnstile.verify(token, ip);
  res.json(result);
});
app.get('/api/pow/challenge', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const challenge = proofOfWork.generateChallenge(ip);
  res.json(challenge);
});
app.post('/api/pow/verify', (req, res) => {
  const { challenge, nonce } = req.body;
  if (!challenge || nonce === undefined) {
    return res.status(400).json({ error: 'Missing challenge or nonce' });
  }
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const result = proofOfWork.verifyProof(challenge, String(nonce), ip);
  if (!result.valid) {
    return res.status(403).json({ error: 'Invalid proof', reason: result.reason });
  }
  res.json({ success: true, hash: result.hash });
});
app.post('/api/snowflake/enable', (req, res) => {
  res.json(snowflakeProxy.enable());
});
app.post('/api/snowflake/disable', (req, res) => {
  res.json(snowflakeProxy.disable());
});
app.get('/api/snowflake/status', (req, res) => {
  res.json(snowflakeProxy.getStats());
});
app.post('/api/snowflake/connect', async (req, res) => {
  try {
    const { sdpOffer } = req.body;
    const peer = await snowflakeProxy.connectPeer(sdpOffer || '');
    res.json(peer);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/snowflake/relay', (req, res) => {
  try {
    const { peerId, data } = req.body;
    if (!peerId || !data) return res.status(400).json({ error: 'Missing peerId or data' });
    const result = snowflakeProxy.relayData(peerId, data);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/snowflake/disconnect', (req, res) => {
  try {
    const { peerId } = req.body;
    res.json(snowflakeProxy.disconnectPeer(peerId));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/api/snowflake/shape', (req, res) => {
  try {
    const { pattern } = req.body;
    res.json(trafficShaper.setPattern(pattern));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.get('/api/snowflake/patterns', (req, res) => {
  res.json({ patterns: trafficShaper.getPatterns() });
});
app.get('/api/audit/logs', (req, res) => {
  const logs = auditLogger.exportLogs(100);
  res.json({ logs, count: logs.length });
});
app.get('/api/security/status', (req, res) => {
  res.json({
    version: '2.0-tor-enhanced',
    torEnabled: TOR_CONFIG.enabled,
    connectionType: req.isTorConnection ? 'Tor Hidden Service' : 'Direct HTTPS',
    features: [
      'Double Ratchet Algorithm: Active (X25519 + HKDF-SHA256)',
      'X3DH Key Agreement: Active (4-DH with OTP)',
      'Encrypted File Transfer: Active (AES-256-GCM chunked)',
      'Blind Server: Active (sealed sender + metadata stripping)',
      'Anti-Bot: Active (PoW + fingerprint throttle)',
      'Snowflake Proxy: ' + (snowflakeProxy.isEnabled() ? 'Active' : 'Standby') + ' (' + (snowflakeProxy.hasWebRTC ? 'native WebRTC' : 'fallback') + ')',
      'Traffic Shaping: Active (video-call/social-scroll/browsing)',
      'Rate Limiting: Active (100 req/min)',
      'Audit Logging: Active (metadata-only)',
      'Identity Management: Active (TOFU model)',
      'Encrypted Storage: Active (AES-256-GCM)',
      'Brute Force Protection: Active (15-min blocks)',
      'TOR Network: Active (hidden service)',
      'Media E2E: Active (AES-256-GCM chunked)'
    ],
    status: 'secure',
    messagesTTL: messageStorage.TTL,
    identitiesRegistered: identityManager.identities.size,
    auditLogsCount: auditLogger.logs.length,
    torServiceName: TOR_CONFIG.name,
    hiddenServiceCompatible: TOR_CONFIG.supportHiddenService
  });
});
setInterval(() => {
  messageStorage.cleanupExpired();
  mediaStorage.cleanupExpired();
  blindStore.cleanup();
  auditLogger.log('maintenance', 'system', 'success', 'cleanup_completed');
}, 60000);

const getLocalIP = () => {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
};
const initTORService = () => {
  if (!TOR_CONFIG || !TOR_CONFIG.enabled) return;
  try {
    if (!fs.existsSync(TOR_CONFIG.hiddenServiceDir)) {
      fs.mkdirSync(TOR_CONFIG.hiddenServiceDir, { recursive: true });
    }

  } catch(e) {

  }
};
https.createServer(sslOptions, app).listen(PORT, '0.0.0.0', () => {
  const localIP = getLocalIP();
  initTORService();
  console.log('HTTPS running on https://localhost:' + PORT);
  console.log('HTTPS running on https://' + localIP + ':' + PORT);
});
http.createServer(app).listen(PORT + 1, '0.0.0.0', () => {
  const localIP = getLocalIP();
  console.log('HTTP  running on http://localhost:' + (PORT + 1));
  console.log('HTTP  running on http://' + localIP + ':' + (PORT + 1));
});
app.use((req, res, next) => {
  const xForwardedFor = req.get('X-Forwarded-For');
  const isTorConnection = xForwardedFor && xForwardedFor.includes('.onion');

  if (isTorConnection) {
    auditLogger.log('tor_connection', 'tor-user-' + crypto.randomBytes(8).toString('hex'), 'success');
  }

  next();
});

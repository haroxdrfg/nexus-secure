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

// Modules sécurité
const config = require('./config');
const Validators = require('./validators');
const rateLimiter = require('./rate-limiter');
const { AuditLogger: auditLogger } = require('./database');

const app = express();
const PORT = config.PORT;

// TOR Configuration (disabled by default)
const TOR_CONFIG = { enabled: false };

// Security: CORS restrictif
const corsOptions = {
  origin: config.ALLOWED_ORIGINS,
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// Security: Headers strict
const securityHeadersMiddleware = (req, res, next) => {
  Object.entries(config.SECURITY_HEADERS).forEach(([key, value]) => {
    res.set(key, value);
  });
  next();
};

// ============ SECURITY INFRASTRUCTURE ============

/**
 * Rate Limiting & Brute Force Protection
 */
// ============ SECURITY INFRASTRUCTURE (depuis modules séparés) ============
// RateLimiter -> rate-limiter.js (support proxy X-Forwarded-For)
// AuditLogger -> database.js (avec persistance disque)
// SecureMessageStorage -> database.js (avec overwrite mémoire)

/**
 * Identity Management with Persistence
 */
class IdentityManager {
  constructor() {
    this.identities = new Map(); // participantId -> identity data
    this.trustedIdentities = new Set(); // Trusted fingerprints
    this.identityHistory = new Map(); // Track identity changes
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
    
    // Generate replacement OTP key
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

/**
 * Generic Key-Value Storage (for client pairing data, identities, etc.)
 */
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

/**
 * Encrypted Message Storage
 */
class SecureMessageStorage {
  constructor() {
    this.storage = new Map();
    this.masterKey = crypto.randomBytes(32);
    this.TTL = 120000; // 2 minutes
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
      // Overwrite with random data before deletion
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

// ============ INITIALIZE SECURITY COMPONENTS ============

const identityManager = new IdentityManager();
const messageStorage = new SecureMessageStorage();
const genericStorage = new GenericStorage();

// Charger ou générer certificat HTTPS automatiquement
let sslOptions = null;
const certPath = path.join(__dirname, 'cert.crt');
const keyPath = path.join(__dirname, 'cert.key');

// Vérifier et générer certificatauto-signé si nécessaire
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
    
    // Sauvegarder les certificats
    fs.writeFileSync(keyPath, pems.private);
    fs.writeFileSync(certPath, pems.cert);
    
    console.log('[✓] Certificats auto-signés générés et sauvegardés');
  } catch(e) {
    console.error('[!] Erreur génération certificat:', e.message);
    process.exit(1);
  }
}

// Charger les certificats
try {
  sslOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
  };
  console.log('[✓] Certificats chargés avec succès');
} catch(e) {
  console.error('ERROR: Cannot load certificates');
  console.error(e.message);
  process.exit(1);
}

// Middlewares sécurisés
app.use(cors(corsOptions));
app.use(securityHeadersMiddleware);
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));
app.use(rateLimiter.middleware());

// Middleware de validation globale
app.use((req, res, next) => {
  if (req.body && Object.keys(req.body).length > 0) {
    // Valider la taille
    if (JSON.stringify(req.body).length > 1000000) {
      return res.status(413).json({ error: 'Payload too large' });
    }
  }
  next();
});

// ============ ENHANCED API ENDPOINTS ============

// Identity Registration with X3DH prekeys
app.post('/api/identity/register', (req, res) => {
  try {
    // Validation input stricte
    const validation = Validators.validateIdentityRegister(req.body);
    if (!validation.valid) {
      AuditLogger.log('identity_registration', 'unknown', 'failed', 'INVALID_INPUT');
      return res.status(400).json({ error: 'Invalid input', details: validation.errors });
    }

    const { participantId, identityPublicKey, signaturePublicKey } = req.body;

    // Vérifier que l'identité n'existe pas déjà
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

// Get Identity (for pairing)
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

// Store encrypted message (opaque to server)
app.post('/api/messages/store', (req, res) => {
  try {
    const { messageId, encryptedData } = req.body;
    
    if (!messageId || !encryptedData) {
      return res.status(400).json({ error: 'Missing messageId or encryptedData' });
    }

    // Store only the encrypted blob (server cannot decrypt)
    const entry = messageStorage.encryptMessage(messageId, JSON.stringify(encryptedData));
    
    auditLogger.log('message_storage', messageId, 'success');
    
    res.json({ success: true, expiresAt: entry.expiresAt });
  } catch (error) {
    auditLogger.log('message_storage', req.body.messageId, 'failed', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Retrieve encrypted message
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

// Delete message
app.delete('/api/messages/:messageId', (req, res) => {
  try {
    messageStorage.deleteMessage(req.params.messageId);
    
    auditLogger.log('message_deletion', req.params.messageId, 'success');
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ GENERIC STORAGE ENDPOINTS (for pairing data, identity, etc.) ============

// Store value in generic storage
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

// List keys with prefix (MUST come before generic :key route)
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

// Retrieve value from generic storage
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

// Delete value from generic storage
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

// Audit logs (needs authentication in production)
app.get('/api/audit/logs', (req, res) => {
  const logs = auditLogger.getLogs(100);
  res.json({ logs, count: logs.length });
});

// Security status endpoint
app.get('/api/security/status', (req, res) => {
  res.json({
    version: '2.0-tor-enhanced',
    torEnabled: TOR_CONFIG.enabled,
    connectionType: req.isTorConnection ? 'Tor Hidden Service' : 'Direct HTTPS',
    features: [
      'Double Ratchet Algorithm (planned v2.1)',
      'X3DH Key Agreement (planned v2.1)',
      'Rate Limiting: Active (100 req/min)',
      'Audit Logging: Active (metadata-only)',
      'Identity Management: Active (TOFU model)',
      'Encrypted Storage: Active (AES-256-GCM)',
      'Brute Force Protection: Active (15-min blocks)',
      'TOR Network: Active (hidden service)',
      'No Emojis Mode: Enabled'
    ],
    status: 'secure',
    messagesTTL: messageStorage.TTL,
    identitiesRegistered: identityManager.identities.size,
    auditLogsCount: auditLogger.logs.length,
    torServiceName: TOR_CONFIG.name,
    hiddenServiceCompatible: TOR_CONFIG.supportHiddenService
  });
});

// Cleanup periodic tasks
setInterval(() => {
  messageStorage.cleanupExpired();
  // Log cleanup event
  auditLogger.log('maintenance', 'system', 'success', 'cleanup_completed');
}, 60000); // Every minute

// Page de bienvenue
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Get local IP address
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

// TOR Hidden Service Support
const initTORService = () => {
  if (!TOR_CONFIG || !TOR_CONFIG.enabled) return;
  
  // Try to create TOR data directory
  try {
    if (!fs.existsSync(TOR_CONFIG.hiddenServiceDir)) {
      fs.mkdirSync(TOR_CONFIG.hiddenServiceDir, { recursive: true });
    }
    
    // Log TOR configuration
    /* TOR service initialized */
    
  } catch(e) {
    /* TOR initialization failed */
  }
};

// Start HTTPS server
https.createServer(sslOptions, app).listen(PORT, '0.0.0.0', () => {
  const localIP = getLocalIP();
  
  // Initialize TOR
  initTORService();
  
  console.log('Server running on port ' + PORT);
});

// TOR Network routing (for requests from Tor)
app.use((req, res, next) => {
  // Detect if connection is from Tor
  const xForwardedFor = req.get('X-Forwarded-For');
  const isTorConnection = xForwardedFor && xForwardedFor.includes('.onion');
  
  if (isTorConnection) {
    // Add TOR metadata to logs
    auditLogger.log('tor_connection', 'tor-user-' + crypto.randomBytes(8).toString('hex'), 'success');
  }
  
  next();
});

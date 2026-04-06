const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

class AuditLogger {
  constructor() {
    this.logFile = path.join(logsDir, 'audit.log');
    this.hmacKey = crypto.randomBytes(32);
    this.logs = [];
  }

  log(eventType, participantId, details = {}, severity = 'INFO') {
    const entry = {
      timestamp: new Date().toISOString(),
      eventType,
      participantIdHash: crypto.createHash('sha256').update(participantId).digest('hex').slice(0, 16),
      severity,
      details: this.sanitizeDetails(details)
    };

    this.logs.push(entry);    if (config.AUDIT.logToFile) {
      this.appendToFile(entry);
    }
  }

  sanitizeDetails(details) {
    const safe = {};
    for (const [key, value] of Object.entries(details)) {
      if (key.includes('key') || key.includes('secret') || key.includes('password')) {
        safe[key] = '[REDACTED]';
      } else if (typeof value === 'string' && value.length > 200) {
        safe[key] = value.substring(0, 200) + '...';
      } else {
        safe[key] = value;
      }
    }
    return safe;
  }

  appendToFile(entry) {
    try {
      const line = JSON.stringify(entry);
      const hmac = crypto.createHmac('sha256', this.hmacKey).update(line).digest('hex');
      fs.appendFileSync(this.logFile, `${line}|${hmac}\n`);
    } catch (e) {
      console.error('Failed to write audit log:', e);
    }
  }

  exportLogs(limit = 100) {
    return this.logs.slice(-limit);
  }

  clear() {
    this.logs = [];
  }
}

class SecureMessageStorage {
  constructor() {
    this.storage = new Map();
    this.expiredChecker = setInterval(() => this.removeExpired(), 30000);
  }

  encryptMessage(messageId, plaintext, participantId) {
    try {
      const masterKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv(config.CRYPTO.algorithm, masterKey, iv);

      const encrypted = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
      const authTag = cipher.getAuthTag();

      const entry = {
        messageId,
        ciphertext: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        masterKey: masterKey.toString('hex'),
        participantId,
        createdAt: Date.now(),
        expiresAt: Date.now() + config.MESSAGE_TTL
      };

      this.storage.set(messageId, entry);
      return entry;
    } catch (e) {
      throw new Error('Encryption failed: ' + e.message);
    }
  }

  decryptMessage(messageId) {
    const entry = this.storage.get(messageId);
    if (!entry) {
      throw new Error('Message not found or expired');
    }

    if (Date.now() > entry.expiresAt) {
      this.storage.delete(messageId);
      throw new Error('Message expired');
    }

    try {
      const decipher = crypto.createDecipheriv(
        config.CRYPTO.algorithm,
        Buffer.from(entry.masterKey, 'hex'),
        Buffer.from(entry.iv, 'hex')
      );

      decipher.setAuthTag(Buffer.from(entry.authTag, 'hex'));
      const decrypted = decipher.update(entry.ciphertext, 'hex', 'utf8') + decipher.final('utf8');

      return decrypted;
    } catch (e) {
      throw new Error('Decryption failed: ' + e.message);
    }
  }

  removeExpired() {
    const now = Date.now();
    for (const [id, entry] of this.storage.entries()) {
      if (now > entry.expiresAt) {
        this.storage.delete(id);
      }
    }
  }

  deleteMessage(messageId) {
    if (this.storage.has(messageId)) {
      const entry = this.storage.get(messageId);      entry.ciphertext = crypto.randomBytes(Buffer.byteLength(entry.ciphertext) / 2).toString('hex');
      entry.masterKey = crypto.randomBytes(32).toString('hex');
      this.storage.delete(messageId);
    }
  }

  clear() {
    this.storage.clear();
  }
}module.exports = {
  AuditLogger: new AuditLogger(),
  SecureMessageStorage: new SecureMessageStorage()
};

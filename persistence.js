/**
 * Secure SQLite Persistence
 * 
 * Stores:
 * - Audit logs (immutable, integrity-checked)
 * - Message metadata (NOT content - only opaque blobs)
 * - Session metadata
 * - User identities (fingerprints only)
 * 
 * CRITICAL: Messages are stored as encrypted blobs
 * Database key derived from master secret (not hardcoded)
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class SecurePersistence {
  constructor(dbPath = './data/nexus-secure.db', masterSecret = null) {
    this.dbPath = dbPath;
    this.dataDir = path.dirname(dbPath);
    
    // Ensure data directory exists
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    }

    // Master secret for DB integrity
    if (!masterSecret) {
      this.masterSecret = crypto.randomBytes(32);
      this.saveMasterSecret();
    } else {
      this.masterSecret = masterSecret;
    }

    // In-memory cache for now (replace with real SQL later)
    // Production should use: better-sqlite3 or pg with encryption
    this.store = {
      sessions: new Map(),
      messages: new Map(),
      identities: new Map(),
      auditLogs: []
    };

    this.integrityKey = crypto.hkdfSync(
      'sha256',
      this.masterSecret,
      Buffer.alloc(0),
      'persistence-integrity',
      32
    );
  }

  /**
   * Save master secret to disk (protect with file perms)
   * Production: use key management service (AWS KMS, Vault)
   */
  saveMasterSecret() {
    const secretPath = path.join(this.dataDir, '.secret');
    
    // Create with restrictive permissions (owner read-only)
    fs.writeFileSync(secretPath, this.masterSecret.toString('hex'), {
      mode: 0o600,
      flag: 'w'
    });
  }

  /**
   * Load master secret from disk
   */
  static loadMasterSecret(dataDir) {
    const secretPath = path.join(dataDir, '.secret');
    
    if (!fs.existsSync(secretPath)) {
      return null;
    }

    try {
      const hex = fs.readFileSync(secretPath, 'utf8').trim();
      return Buffer.from(hex, 'hex');
    } catch (e) {
      throw new Error('Failed to load master secret: ' + e.message);
    }
  }

  /**
   * Store session metadata
   */
  storeSession(sessionId, participantId, peerId, ecdhPublicKeyHash) {
    if (!sessionId || !participantId || !peerId) {
      throw new Error('Missing session data');
    }

    const session = {
      sessionId,
      participantId,
      peerId,
      ecdhPublicKeyHash, // Never store the actual key
      createdAt: Date.now(),
      state: 'active',
      messageCount: 0
    };

    this.store.sessions.set(sessionId, session);
    this.auditLog('session_created', participantId, { sessionId, peerId });

    return session;
  }

  /**
   * Store message metadata (NOT content)
   * Content is encrypted blob - we store metadata only
   */
  storeMessageMetadata(messageId, sessionId, senderIdHash, recipientIdHash, size, nonce) {
    if (!messageId || !sessionId || !senderIdHash) {
      throw new Error('Missing message metadata');
    }

    const message = {
      messageId,
      sessionId,
      senderIdHash,
      recipientIdHash,
      size,
      nonce,
      storedAt: Date.now(),
      expiresAt: Date.now() + (2 * 60 * 1000) // 2 min TTL
    };

    this.store.messages.set(messageId, message);
    this.auditLog('message_stored', senderIdHash, { messageId, size });

    return message;
  }

  /**
   * Store identity fingerprint (NOT the key itself)
   */
  storeIdentity(participantId, fingerprintHash, ecdsaPublicKeyHash, createdAt = null) {
    if (!participantId || !fingerprintHash) {
      throw new Error('Missing identity data');
    }

    const identity = {
      participantId,
      fingerprintHash,
      ecdsaPublicKeyHash,
      createdAt: createdAt || Date.now(),
      lastSeen: Date.now(),
      trustLevel: 'unverified' // TOFU: trust on first use
    };

    this.store.identities.set(participantId, identity);
    this.auditLog('identity_registered', participantId, { fingerprintHash });

    return identity;
  }

  /**
   * Audit logging - integrity protected
   */
  auditLog(eventType, participantIdHash, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      eventType,
      participantIdHash: crypto.createHash('sha256').update(participantIdHash).digest('hex').slice(0, 16),
      details: this.sanitizeDetails(details),
      integrity: null // Will be filled with HMAC
    };

    // Compute HMAC for integrity
    const logString = JSON.stringify({
      timestamp: entry.timestamp,
      eventType: entry.eventType,
      participantIdHash: entry.participantIdHash,
      details: entry.details
    });

    entry.integrity = crypto
      .createHmac('sha256', this.integrityKey)
      .update(logString)
      .digest('hex');

    this.store.auditLogs.push(entry);

    // Write to disk immediately (no buffering)
    this.appendAuditLogToDisk(entry);

    return entry;
  }

  /**
   * Append audit log to immutable file
   */
  appendAuditLogToDisk(entry) {
    const logPath = path.join(this.dataDir, 'audit.log');
    const line = JSON.stringify(entry) + '\n';

    try {
      fs.appendFileSync(logPath, line, { mode: 0o600 });
    } catch (e) {
      console.error('Failed to write audit log:', e);
    }
  }

  /**
   * Verify audit log integrity
   * Ensures logs haven't been tampered with
   */
  verifyAuditLogIntegrity(entry) {
    if (!entry.integrity) {
      return false;
    }

    const logString = JSON.stringify({
      timestamp: entry.timestamp,
      eventType: entry.eventType,
      participantIdHash: entry.participantIdHash,
      details: entry.details
    });

    const expected = crypto
      .createHmac('sha256', this.integrityKey)
      .update(logString)
      .digest('hex');

    return entry.integrity === expected;
  }

  /**
   * Sanitize details to avoid storing sensitive data
   */
  sanitizeDetails(details) {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(details)) {
      if (key.includes('key') || key.includes('secret') || key.includes('password')) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'string' && value.length > 200) {
        sanitized[key] = value.substring(0, 200) + '...';
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Get message metadata (not content)
   */
  getMessageMetadata(messageId) {
    const message = this.store.messages.get(messageId);
    if (!message) {
      throw new Error('Message not found');
    }

    if (Date.now() > message.expiresAt) {
      this.store.messages.delete(messageId);
      throw new Error('Message expired');
    }

    return message;
  }

  /**
   * List sessions for participant
   */
  getParticipantSessions(participantId) {
    const sessions = [];
    
    for (const [sessionId, session] of this.store.sessions.entries()) {
      if (session.participantId === participantId) {
        sessions.push(session);
      }
    }

    return sessions;
  }

  /**
   * Get identity
   */
  getIdentity(participantId) {
    return this.store.identities.get(participantId) || null;
  }

  /**
   * Export audit logs for analysis
   * Verify integrity of each entry
   */
  exportAuditLogs(limit = null) {
    const logs = this.store.auditLogs;
    const toExport = limit ? logs.slice(-limit) : logs;

    const verified = toExport.map(entry => ({
      ...entry,
      integrityValid: this.verifyAuditLogIntegrity(entry)
    }));

    return verified;
  }

  /**
   * Cleanup expired messages
   */
  cleanupExpiredMessages() {
    const now = Date.now();
    let count = 0;

    for (const [messageId, message] of this.store.messages.entries()) {
      if (now > message.expiresAt) {
        this.store.messages.delete(messageId);
        count++;
      }
    }

    return count;
  }

  /**
   * Database statistics
   */
  getStats() {
    return {
      sessions: this.store.sessions.size,
      messages: this.store.messages.size,
      identities: this.store.identities.size,
      auditLogs: this.store.auditLogs.length,
      dataDir: this.dataDir
    };
  }
}

module.exports = SecurePersistence;

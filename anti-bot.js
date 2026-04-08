'use strict';

const crypto = require('crypto');
const https = require('https');

const MAX_MAP_SIZE = 50000;

function evictOldest(map, maxSize) {
  if (map.size <= maxSize) return;
  const excess = map.size - maxSize;
  const iter = map.keys();
  for (let i = 0; i < excess; i++) {
    map.delete(iter.next().value);
  }
}

class TurnstileVerifier {
  constructor(secretKey) {
    if (!secretKey || typeof secretKey !== 'string') {
      throw new Error('Cloudflare Turnstile secret key required');
    }
    this.secretKey = secretKey;
    this.verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    this.verifiedTokens = new Map();
    this.TOKEN_TTL = 300000;
    this.MAX_TOKENS = MAX_MAP_SIZE;
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }

  verify(token, remoteIP) {
    return new Promise((resolve, reject) => {
      if (!token || typeof token !== 'string') {
        return resolve({ success: false, reason: 'missing_token' });
      }
      if (token.length > 2048) {
        return resolve({ success: false, reason: 'token_too_long' });
      }
      const cached = this.verifiedTokens.get(token);
      if (cached) {
        if (Date.now() - cached.timestamp < this.TOKEN_TTL) {
          if (cached.ip !== remoteIP) {
            return resolve({ success: false, reason: 'ip_mismatch' });
          }
          return resolve({ success: true, cached: true });
        }
        this.verifiedTokens.delete(token);
      }
      const postData = JSON.stringify({
        secret: this.secretKey,
        response: token,
        remoteip: remoteIP || undefined
      });
      const options = {
        hostname: 'challenges.cloudflare.com',
        port: 443,
        path: '/turnstile/v0/siteverify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: 5000
      };
      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            const result = JSON.parse(body);
            if (result.success) {
              evictOldest(this.verifiedTokens, this.MAX_TOKENS);
              this.verifiedTokens.set(token, { timestamp: Date.now(), ip: remoteIP });
            }
            resolve({
              success: result.success,
              challengeTs: result.challenge_ts,
              hostname: result.hostname,
              errorCodes: result['error-codes']
            });
          } catch {
            resolve({ success: false, reason: 'invalid_response' });
          }
        });
      });
      req.on('error', () => {
        resolve({ success: false, reason: 'network_error' });
      });
      req.on('timeout', () => {
        req.destroy();
        resolve({ success: false, reason: 'timeout' });
      });
      req.write(postData);
      req.end();
    });
  }

  middleware(options = {}) {
    const excludePaths = options.excludePaths || [];
    const headerName = options.headerName || 'x-turnstile-token';
    return async (req, res, next) => {
      for (const p of excludePaths) {
        if (req.path.startsWith(p)) return next();
      }
      const token = req.headers[headerName] || req.body?.turnstileToken;
      if (!token) {
        return res.status(403).json({ error: 'Anti-bot verification required', code: 'TURNSTILE_REQUIRED' });
      }
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
      const result = await this.verify(token, ip);
      if (!result.success) {
        return res.status(403).json({ error: 'Anti-bot verification failed', code: 'TURNSTILE_FAILED', reason: result.reason || result.errorCodes });
      }
      req.turnstileVerified = true;
      next();
    };
  }

  cleanup() {
    const now = Date.now();
    for (const [token, data] of this.verifiedTokens) {
      if (now - data.timestamp > this.TOKEN_TTL) {
        this.verifiedTokens.delete(token);
      }
    }
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    this.verifiedTokens.clear();
  }
}

class ProofOfWork {
  constructor(difficulty = 4, options = {}) {
    this.baseDifficulty = difficulty;
    this.difficulty = difficulty;
    this.maxDifficulty = options.maxDifficulty || 6;
    this.challenges = new Map();
    this.CHALLENGE_TTL = 120000;
    this.MAX_NONCE_LENGTH = 64;
    this.MAX_CHALLENGES = MAX_MAP_SIZE;
    this.solveTimes = [];
    this.ADAPT_WINDOW = 60000;
    this.ADAPT_THRESHOLD_HIGH = 100;
    this.ADAPT_THRESHOLD_LOW = 20;
    this.cleanupInterval = setInterval(() => this.cleanup(), 30000);
    this.adaptInterval = setInterval(() => this.adaptDifficulty(), 15000);
  }

  adaptDifficulty() {
    const now = Date.now();
    this.solveTimes = this.solveTimes.filter(t => now - t < this.ADAPT_WINDOW);
    const rate = this.solveTimes.length;
    if (rate > this.ADAPT_THRESHOLD_HIGH && this.difficulty < this.maxDifficulty) {
      this.difficulty++;
    } else if (rate < this.ADAPT_THRESHOLD_LOW && this.difficulty > this.baseDifficulty) {
      this.difficulty--;
    }
  }

  getDifficulty() {
    return this.difficulty;
  }

  generateChallenge(clientIP) {
    evictOldest(this.challenges, this.MAX_CHALLENGES);
    const challenge = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();
    this.challenges.set(challenge, { timestamp, solved: false, ip: clientIP || null });
    return { challenge, difficulty: this.difficulty, timestamp };
  }

  verifyProof(challenge, nonce, clientIP) {
    if (typeof nonce === 'string' && nonce.length > this.MAX_NONCE_LENGTH) {
      return { valid: false, reason: 'nonce_too_long' };
    }
    const entry = this.challenges.get(challenge);
    if (!entry) return { valid: false, reason: 'unknown_challenge' };
    if (Date.now() - entry.timestamp > this.CHALLENGE_TTL) {
      this.challenges.delete(challenge);
      return { valid: false, reason: 'expired' };
    }
    if (entry.solved) return { valid: false, reason: 'already_used' };
    if (entry.ip && clientIP && entry.ip !== clientIP) {
      return { valid: false, reason: 'ip_mismatch' };
    }
    const hash = crypto.createHash('sha256')
      .update(challenge + String(nonce))
      .digest('hex');
    const prefix = '0'.repeat(entry.difficulty || this.difficulty);
    if (!hash.startsWith(prefix)) {
      return { valid: false, reason: 'invalid_proof' };
    }
    entry.solved = true;
    this.solveTimes.push(Date.now());
    return { valid: true, hash, difficulty: entry.difficulty || this.difficulty };
  }

  middleware() {
    return (req, res, next) => {
      const powChallenge = req.headers['x-pow-challenge'];
      const powNonce = req.headers['x-pow-nonce'];
      if (!powChallenge || !powNonce) {
        return res.status(403).json({ error: 'Proof of work required', code: 'POW_REQUIRED' });
      }
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
      const result = this.verifyProof(powChallenge, powNonce, ip);
      if (!result.valid) {
        return res.status(403).json({ error: 'Invalid proof of work', code: 'POW_FAILED', reason: result.reason });
      }
      req.powVerified = true;
      next();
    };
  }

  cleanup() {
    const now = Date.now();
    for (const [ch, data] of this.challenges) {
      if (now - data.timestamp > this.CHALLENGE_TTL) {
        this.challenges.delete(ch);
      }
    }
    this.solveTimes = this.solveTimes.filter(t => now - t < this.ADAPT_WINDOW);
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    clearInterval(this.adaptInterval);
    this.challenges.clear();
    this.solveTimes = [];
  }
}

class FingerprintThrottle {
  constructor(options = {}) {
    this.fingerprints = new Map();
    this.MAX_PER_FP = options.maxPerFP || 20;
    this.WINDOW = options.window || 60000;
    this.MAX_FINGERPRINTS = MAX_MAP_SIZE;
    this.cleanupInterval = setInterval(() => this.cleanup(), 30000);
  }

  static computeFingerprint(req) {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.connection?.remoteAddress || '';
    const ua = req.headers['user-agent'] || '';
    const lang = req.headers['accept-language'] || '';
    const accept = req.headers['accept-encoding'] || '';
    return crypto.createHash('sha256').update(ip + '|' + ua + '|' + lang + '|' + accept).digest('hex').slice(0, 32);
  }

  check(fingerprint) {
    if (!fingerprint) return { allowed: true };
    const now = Date.now();
    let entry = this.fingerprints.get(fingerprint);
    if (!entry) {
      evictOldest(this.fingerprints, this.MAX_FINGERPRINTS);
      entry = { requests: [], blocked: false };
      this.fingerprints.set(fingerprint, entry);
    }
    entry.requests = entry.requests.filter(t => now - t < this.WINDOW);
    if (entry.requests.length >= this.MAX_PER_FP) {
      entry.blocked = true;
      return { allowed: false, reason: 'fingerprint_throttled' };
    }
    entry.requests.push(now);
    return { allowed: true, remaining: this.MAX_PER_FP - entry.requests.length };
  }

  middleware() {
    return (req, res, next) => {
      const fp = FingerprintThrottle.computeFingerprint(req);
      const result = this.check(fp);
      if (!result.allowed) {
        return res.status(429).json({ error: 'Too many requests from this client', code: 'FP_THROTTLED' });
      }
      req.clientFingerprint = fp;
      next();
    };
  }

  cleanup() {
    const now = Date.now();
    for (const [fp, entry] of this.fingerprints) {
      entry.requests = entry.requests.filter(t => now - t < this.WINDOW);
      if (entry.requests.length === 0) this.fingerprints.delete(fp);
    }
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    this.fingerprints.clear();
  }
}

module.exports = { TurnstileVerifier, ProofOfWork, FingerprintThrottle };

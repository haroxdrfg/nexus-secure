'use strict';

const crypto = require('crypto');
const https = require('https');

class TurnstileVerifier {
  constructor(secretKey) {
    if (!secretKey || typeof secretKey !== 'string') {
      throw new Error('Cloudflare Turnstile secret key required');
    }
    this.secretKey = secretKey;
    this.verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    this.verifiedTokens = new Map();
    this.TOKEN_TTL = 300000;
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
  constructor(difficulty = 4) {
    this.difficulty = difficulty;
    this.challenges = new Map();
    this.CHALLENGE_TTL = 120000;
    this.cleanupInterval = setInterval(() => this.cleanup(), 30000);
  }

  generateChallenge() {
    const challenge = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();
    this.challenges.set(challenge, { timestamp, solved: false });
    return { challenge, difficulty: this.difficulty, timestamp };
  }

  verifyProof(challenge, nonce) {
    const entry = this.challenges.get(challenge);
    if (!entry) return { valid: false, reason: 'unknown_challenge' };
    if (Date.now() - entry.timestamp > this.CHALLENGE_TTL) {
      this.challenges.delete(challenge);
      return { valid: false, reason: 'expired' };
    }
    if (entry.solved) return { valid: false, reason: 'already_used' };
    const hash = crypto.createHash('sha256')
      .update(challenge + nonce)
      .digest('hex');
    const prefix = '0'.repeat(this.difficulty);
    if (!hash.startsWith(prefix)) {
      return { valid: false, reason: 'invalid_proof' };
    }
    entry.solved = true;
    return { valid: true, hash };
  }

  middleware() {
    return (req, res, next) => {
      const powChallenge = req.headers['x-pow-challenge'];
      const powNonce = req.headers['x-pow-nonce'];
      if (!powChallenge || !powNonce) {
        return res.status(403).json({ error: 'Proof of work required', code: 'POW_REQUIRED' });
      }
      const result = this.verifyProof(powChallenge, powNonce);
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
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    this.challenges.clear();
  }
}

class FingerprintThrottle {
  constructor() {
    this.fingerprints = new Map();
    this.MAX_PER_FP = 20;
    this.WINDOW = 60000;
    this.cleanupInterval = setInterval(() => this.cleanup(), 30000);
  }

  check(fingerprint) {
    if (!fingerprint) return { allowed: true };
    const now = Date.now();
    let entry = this.fingerprints.get(fingerprint);
    if (!entry) {
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
      const fp = req.headers['x-client-fingerprint'];
      if (fp) {
        const result = this.check(fp);
        if (!result.allowed) {
          return res.status(429).json({ error: 'Too many requests from this client', code: 'FP_THROTTLED' });
        }
      }
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

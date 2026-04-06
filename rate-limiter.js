const config = require('./config');

class RateLimiter {
  constructor() {
    this.ipLimits = new Map();
    this.idLimits = new Map();
    this.blockedIPs = new Map();
    this.blockedIds = new Map();
  }

  getClientIP(req) {    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) {
      return xForwardedFor.split(',')[0].trim();
    }
    return req.ip || req.connection.remoteAddress || 'unknown';
  }

  isIPBlocked(ip) {
    if (!this.blockedIPs.has(ip)) return false;

    const blockTime = this.blockedIPs.get(ip);
    if (Date.now() - blockTime > config.RATE_LIMIT.blockDuration) {
      this.blockedIPs.delete(ip);
      return false;
    }
    return true;
  }

  isIdBlocked(participantId) {
    if (!this.blockedIds.has(participantId)) return false;

    const blockTime = this.blockedIds.get(participantId);
    if (Date.now() - blockTime > config.RATE_LIMIT.blockDuration) {
      this.blockedIds.delete(participantId);
      return false;
    }
    return true;
  }

  checkIPLimit(ip) {
    if (this.isIPBlocked(ip)) {
      return {
        allowed: false,
        reason: 'IP temporarily blocked due to rate limit violation',
        retryAfter: Math.ceil((this.blockedIPs.get(ip) + config.RATE_LIMIT.blockDuration - Date.now()) / 1000),
        limitType: 'ip'
      };
    }

    const now = Date.now();
    let record = this.ipLimits.get(ip);

    if (!record || now > record.resetTime) {
      this.ipLimits.set(ip, { count: 1, resetTime: now + config.RATE_LIMIT.timeWindow });
      return { allowed: true, limitType: 'ip' };
    }

    record.count++;
    if (record.count > config.RATE_LIMIT.maxRequests) {
      this.blockedIPs.set(ip, now);
      return {
        allowed: false,
        reason: 'Rate limit exceeded',
        retryAfter: Math.ceil(config.RATE_LIMIT.timeWindow / 1000),
        limitType: 'ip'
      };
    }

    return { allowed: true, remaining: config.RATE_LIMIT.maxRequests - record.count, limitType: 'ip' };
  }

  checkIdLimit(participantId) {
    if (!participantId) return { allowed: true, limitType: 'none' };

    if (this.isIdBlocked(participantId)) {
      return {
        allowed: false,
        reason: 'Identity temporarily blocked due to rate limit violation',
        retryAfter: Math.ceil((this.blockedIds.get(participantId) + config.RATE_LIMIT.blockDuration - Date.now()) / 1000),
        limitType: 'id'
      };
    }

    const now = Date.now();
    let record = this.idLimits.get(participantId);

    if (!record || now > record.resetTime) {
      this.idLimits.set(participantId, { count: 1, resetTime: now + config.RATE_LIMIT.timeWindow });
      return { allowed: true, limitType: 'id' };
    }

    record.count++;    const idLimit = Math.max(config.RATE_LIMIT.maxRequests / 2, 50);

    if (record.count > idLimit) {
      this.blockedIds.set(participantId, now);
      return {
        allowed: false,
        reason: 'Identity rate limit exceeded',
        retryAfter: Math.ceil(config.RATE_LIMIT.timeWindow / 1000),
        limitType: 'id'
      };
    }

    return { allowed: true, remaining: idLimit - record.count, limitType: 'id' };
  }

  middleware() {
    return (req, res, next) => {
      const ip = this.getClientIP(req);      const ipCheck = this.checkIPLimit(ip);
      if (!ipCheck.allowed) {
        res.set('Retry-After', ipCheck.retryAfter);
        return res.status(429).json({
          error: ipCheck.reason,
          retryAfter: ipCheck.retryAfter,
          limitType: 'ip'
        });
      }      const participantId = req.user?.sub || req.body?.participantId;
      if (participantId) {
        const idCheck = this.checkIdLimit(participantId);
        if (!idCheck.allowed) {
          res.set('Retry-After', idCheck.retryAfter);
          return res.status(429).json({
            error: idCheck.reason,
            retryAfter: idCheck.retryAfter,
            limitType: 'id'
          });
        }
      }

      res.set('X-RateLimit-Remaining', ipCheck.remaining || config.RATE_LIMIT.maxRequests);
      next();
    };
  }

  clear() {
    this.ipLimits.clear();
    this.idLimits.clear();
    this.blockedIPs.clear();
    this.blockedIds.clear();
  }
}

module.exports = new RateLimiter();

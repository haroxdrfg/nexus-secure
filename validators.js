class Validators {
  static isValidBase64(str) {
    try {
      return Buffer.from(str, 'base64').toString('base64') === str;
    } catch {
      return false;
    }
  }

  static isValidHex(str, length = null) {
    if (typeof str !== 'string') return false;
    if (!/^[a-f0-9]*$/i.test(str)) return false;
    return length ? str.length === length : true;
  }

  static isValidParticipantId(id) {
    return typeof id === 'string' &&
           id.length >= 10 &&
           id.length <= 128 &&
           /^[a-zA-Z0-9_-]*$/.test(id);
  }

  static isValidPublicKey(key) {
    return typeof key === 'string' &&
           key.length > 50 &&
           key.length < 2000 &&
           (key.startsWith('-----BEGIN PUBLIC KEY-----') ||
            Validators.isValidBase64(key) ||
            Validators.isValidHex(key));
  }

  static isValidMessage(msg) {
    return typeof msg === 'object' &&
           msg !== null &&
           typeof msg.ciphertext === 'string' &&
           typeof msg.iv === 'string' &&
           typeof msg.nonce === 'string' &&
           msg.ciphertext.length > 0 &&
           msg.ciphertext.length < 100000;
  }

  static isValidFingerprint(fp) {
    return typeof fp === 'string' &&
           /^[a-f0-9]{32,64}$/i.test(fp);
  }

  static sanitizeString(str, maxLength = 1000) {
    if (typeof str !== 'string') return '';
    return str.substring(0, maxLength).trim();
  }

  static validateIdentityRegister(body) {
    const errors = [];

    if (!Validators.isValidParticipantId(body.participantId)) {
      errors.push('Invalid participantId');
    }

    if (!Validators.isValidPublicKey(body.identityPublicKey)) {
      errors.push('Invalid identityPublicKey');
    }

    if (body.signaturePublicKey && !Validators.isValidPublicKey(body.signaturePublicKey)) {
      errors.push('Invalid signaturePublicKey');
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  }

  static validateMessageSubmit(body) {
    const errors = [];

    if (!body.recipientId || !Validators.isValidParticipantId(body.recipientId)) {
      errors.push('Invalid recipientId');
    }

    if (!Validators.isValidMessage(body.encryptedMessage)) {
      errors.push('Invalid encryptedMessage format');
    }

    if (body.senderId && !Validators.isValidParticipantId(body.senderId)) {
      errors.push('Invalid senderId');
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  }

  static validatePairingRequest(body) {
    const errors = [];

    if (!Validators.isValidParticipantId(body.peerId)) {
      errors.push('Invalid peerId');
    }

    if (!Validators.isValidPublicKey(body.ephemeralPublicKey)) {
      errors.push('Invalid ephemeralPublicKey');
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true };
  }
}

module.exports = Validators;

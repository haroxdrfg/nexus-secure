'use strict';

const crypto = require('crypto');

function hkdfDerive(ikm, salt, info, length) {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info), length));
}

function generateIdentityKeyPair() {
  return crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
}

function generateEphemeralKeyPair() {
  return generateIdentityKeyPair();
}

function generateSignedPreKey(identityPrivateKey) {
  const kp = generateIdentityKeyPair();
  const sign = crypto.createPrivateKey({ key: identityPrivateKey, format: 'der', type: 'pkcs8' });
  const sigKp = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  const signature = crypto.sign(null, kp.publicKey, crypto.createPrivateKey({ key: sigKp.privateKey, format: 'der', type: 'pkcs8' }));
  return {
    keyPair: kp,
    signature,
    signingKeyPair: sigKp
  };
}

function generateOneTimePreKeys(count) {
  const keys = [];
  for (let i = 0; i < count; i++) {
    keys.push({ id: i, ...generateIdentityKeyPair() });
  }
  return keys;
}

function x25519DH(privateKeyDER, publicKeyDER) {
  const privKey = crypto.createPrivateKey({ key: privateKeyDER, format: 'der', type: 'pkcs8' });
  const pubKey = crypto.createPublicKey({ key: publicKeyDER, format: 'der', type: 'spki' });
  return crypto.diffieHellman({ privateKey: privKey, publicKey: pubKey });
}

function x3dhInitiator(identityKeyA, ephemeralKeyA, identityKeyB, signedPreKeyB, oneTimePreKeyB) {
  const dh1 = x25519DH(identityKeyA.privateKey, signedPreKeyB.publicKey);
  const dh2 = x25519DH(ephemeralKeyA.privateKey, identityKeyB.publicKey);
  const dh3 = x25519DH(ephemeralKeyA.privateKey, signedPreKeyB.publicKey);
  let masterInput = Buffer.concat([dh1, dh2, dh3]);
  if (oneTimePreKeyB) {
    const dh4 = x25519DH(ephemeralKeyA.privateKey, oneTimePreKeyB.publicKey);
    masterInput = Buffer.concat([masterInput, dh4]);
  }
  const salt = Buffer.alloc(32, 0);
  const derived = hkdfDerive(masterInput, salt, 'x3dh-nexus-secure', 64);
  return {
    rootKey: derived.slice(0, 32),
    chainKey: derived.slice(32, 64)
  };
}

function x3dhResponder(identityKeyB, signedPreKeyB, identityKeyA_pub, ephemeralKeyA_pub, oneTimePreKeyB) {
  const dh1 = x25519DH(signedPreKeyB.privateKey, identityKeyA_pub);
  const dh2 = x25519DH(identityKeyB.privateKey, ephemeralKeyA_pub);
  const dh3 = x25519DH(signedPreKeyB.privateKey, ephemeralKeyA_pub);
  let masterInput = Buffer.concat([dh1, dh2, dh3]);
  if (oneTimePreKeyB) {
    const dh4 = x25519DH(oneTimePreKeyB.privateKey, ephemeralKeyA_pub);
    masterInput = Buffer.concat([masterInput, dh4]);
  }
  const salt = Buffer.alloc(32, 0);
  const derived = hkdfDerive(masterInput, salt, 'x3dh-nexus-secure', 64);
  return {
    rootKey: derived.slice(0, 32),
    chainKey: derived.slice(32, 64)
  };
}

function kdfRootKey(rootKey, dhOutput) {
  const derived = hkdfDerive(dhOutput, rootKey, 'ratchet-root', 64);
  return {
    newRootKey: derived.slice(0, 32),
    newChainKey: derived.slice(32, 64)
  };
}

function kdfChainKey(chainKey) {
  const messageKey = crypto.createHmac('sha256', chainKey).update(Buffer.from([0x01])).digest();
  const nextChainKey = crypto.createHmac('sha256', chainKey).update(Buffer.from([0x02])).digest();
  return { messageKey, nextChainKey };
}

function encryptMessage(messageKey, plaintext, associatedData) {
  const derived = hkdfDerive(messageKey, Buffer.alloc(32, 0), 'message-encrypt', 44);
  const encKey = derived.slice(0, 32);
  const iv = derived.slice(32, 44);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  if (associatedData) cipher.setAAD(Buffer.from(associatedData));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return {
    ciphertext: ct.toString('base64'),
    tag: cipher.getAuthTag().toString('base64')
  };
}

function decryptMessage(messageKey, encrypted, associatedData) {
  const derived = hkdfDerive(messageKey, Buffer.alloc(32, 0), 'message-encrypt', 44);
  const encKey = derived.slice(0, 32);
  const iv = derived.slice(32, 44);
  const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
  if (associatedData) decipher.setAAD(Buffer.from(associatedData));
  decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
  const pt = Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
    decipher.final()
  ]);
  return pt.toString('utf8');
}

class DoubleRatchetSession {
  constructor(rootKey, chainKey, isInitiator) {
    this.rootKey = rootKey;
    this.sendChainKey = isInitiator ? chainKey : null;
    this.recvChainKey = isInitiator ? null : chainKey;
    this.sendCounter = 0;
    this.recvCounter = 0;
    this.prevSendCounter = 0;
    this.dhKeyPair = generateEphemeralKeyPair();
    this.remoteDHPublicKey = null;
    this.skippedKeys = new Map();
    this.maxSkip = 100;
    this.isInitiator = isInitiator;
  }

  setRemoteDHKey(remotePubKeyDER) {
    if (this.remoteDHPublicKey &&
        Buffer.compare(this.remoteDHPublicKey, remotePubKeyDER) === 0) {
      return;
    }
    this.remoteDHPublicKey = remotePubKeyDER;
    const dhOutput = x25519DH(this.dhKeyPair.privateKey, remotePubKeyDER);
    if (!this.recvChainKey) {
      const { newRootKey, newChainKey } = kdfRootKey(this.rootKey, dhOutput);
      this.rootKey = newRootKey;
      this.recvChainKey = newChainKey;
      this.recvCounter = 0;
    }
  }

  dhRatchetStep() {
    this.prevSendCounter = this.sendCounter;
    this.sendCounter = 0;
    this.dhKeyPair = generateEphemeralKeyPair();
    const dhOutput = x25519DH(this.dhKeyPair.privateKey, this.remoteDHPublicKey);
    const { newRootKey, newChainKey } = kdfRootKey(this.rootKey, dhOutput);
    this.rootKey = newRootKey;
    this.sendChainKey = newChainKey;
  }

  encrypt(plaintext) {
    if (!this.sendChainKey) {
      if (!this.remoteDHPublicKey) {
        throw new Error('No remote DH key set, cannot encrypt');
      }
      this.dhRatchetStep();
    }
    const { messageKey, nextChainKey } = kdfChainKey(this.sendChainKey);
    this.sendChainKey = nextChainKey;
    const counter = this.sendCounter++;
    const ad = JSON.stringify({ counter, dhPub: this.dhKeyPair.publicKey.toString('base64') });
    const encrypted = encryptMessage(messageKey, plaintext, ad);
    return {
      counter,
      prevCounter: this.prevSendCounter,
      dhPublicKey: this.dhKeyPair.publicKey,
      ciphertext: encrypted.ciphertext,
      tag: encrypted.tag
    };
  }

  skipKeys(until) {
    if (until - this.recvCounter > this.maxSkip) {
      throw new Error('Too many skipped messages');
    }
    while (this.recvCounter < until) {
      const { messageKey, nextChainKey } = kdfChainKey(this.recvChainKey);
      this.recvChainKey = nextChainKey;
      const skippedId = this.remoteDHPublicKey.toString('base64') + ':' + this.recvCounter;
      this.skippedKeys.set(skippedId, messageKey);
      this.recvCounter++;
    }
  }

  trySkippedKey(dhPub, counter) {
    const skippedId = dhPub.toString('base64') + ':' + counter;
    if (this.skippedKeys.has(skippedId)) {
      const key = this.skippedKeys.get(skippedId);
      this.skippedKeys.delete(skippedId);
      return key;
    }
    return null;
  }

  decrypt(message) {
    const skippedKey = this.trySkippedKey(message.dhPublicKey, message.counter);
    if (skippedKey) {
      const ad = JSON.stringify({ counter: message.counter, dhPub: message.dhPublicKey.toString('base64') });
      return decryptMessage(skippedKey, { ciphertext: message.ciphertext, tag: message.tag }, ad);
    }
    const isNewRatchet = !this.remoteDHPublicKey ||
      Buffer.compare(this.remoteDHPublicKey, message.dhPublicKey) !== 0;
    if (isNewRatchet) {
      if (this.remoteDHPublicKey && this.recvChainKey) {
        this.skipKeys(message.prevCounter);
      }
      this.setRemoteDHKey(message.dhPublicKey);
      if (isNewRatchet && this.remoteDHPublicKey) {
        const dhOut = x25519DH(this.dhKeyPair.privateKey, message.dhPublicKey);
        const { newRootKey, newChainKey } = kdfRootKey(this.rootKey, dhOut);
        this.rootKey = newRootKey;
        this.recvChainKey = newChainKey;
        this.recvCounter = 0;
      }
    }
    this.skipKeys(message.counter);
    const { messageKey, nextChainKey } = kdfChainKey(this.recvChainKey);
    this.recvChainKey = nextChainKey;
    this.recvCounter++;
    const ad = JSON.stringify({ counter: message.counter, dhPub: message.dhPublicKey.toString('base64') });
    return decryptMessage(messageKey, { ciphertext: message.ciphertext, tag: message.tag }, ad);
  }

  getState() {
    return {
      sendCounter: this.sendCounter,
      recvCounter: this.recvCounter,
      skippedKeys: this.skippedKeys.size,
      hasRemoteKey: !!this.remoteDHPublicKey
    };
  }
}

function createSessionPair() {
  const identityA = generateIdentityKeyPair();
  const identityB = generateIdentityKeyPair();
  const ephemeralA = generateEphemeralKeyPair();
  const signedPreKeyB = generateEphemeralKeyPair();
  const oneTimePreKeyB = generateEphemeralKeyPair();
  const initKeys = x3dhInitiator(identityA, ephemeralA, { publicKey: identityB.publicKey }, { publicKey: signedPreKeyB.publicKey }, { publicKey: oneTimePreKeyB.publicKey });
  const respKeys = x3dhResponder(identityB, signedPreKeyB, identityA.publicKey, ephemeralA.publicKey, oneTimePreKeyB);
  const sessionA = new DoubleRatchetSession(initKeys.rootKey, initKeys.chainKey, true);
  const sessionB = new DoubleRatchetSession(respKeys.rootKey, respKeys.chainKey, false);
  return { sessionA, sessionB };
}

module.exports = {
  generateIdentityKeyPair,
  generateEphemeralKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  x3dhInitiator,
  x3dhResponder,
  kdfRootKey,
  kdfChainKey,
  encryptMessage,
  decryptMessage,
  DoubleRatchetSession,
  createSessionPair
};

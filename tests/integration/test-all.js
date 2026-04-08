'use strict';

const crypto = require('crypto');

const { ALLOWED_FILE_TYPES, MAX_FILE_SIZE_BYTES, validateFile, generateFileKeyPair, deriveFileAESKey, encryptFile, decryptFile, encryptFileName, decryptFileName, senderEncryptFile, recipientDecryptFile } = require('./file-encrypt');
const { DoubleRatchetSession, createSessionPair, generateIdentityKeyPair, generateEphemeralKeyPair, x3dhInitiator, x3dhResponder, kdfChainKey, encryptMessage, decryptMessage } = require('./double-ratchet');
const { TurnstileVerifier, ProofOfWork, FingerprintThrottle } = require('./anti-bot');
const { BlindEnvelopeStore, MetadataStripper, SealedSender, UnlinkableDelivery } = require('./blind-server');
const { SnowflakeProxy, TrafficShaper, DomainFronting } = require('./snowflake');

let passed = 0;
let failed = 0;
const errors = [];

function assert(condition, label) {
  if (condition) {
    passed++;
    console.log('  [OK] ' + label);
  } else {
    failed++;
    errors.push(label);
    console.log('  [FAIL] ' + label);
  }
}

async function runTests() {
  console.log('=== NEXUS SECURE - Integration Tests ===\n');

  console.log('1. Encrypted File Transfer');

  const recipientKP = generateFileKeyPair();

  const pdfContent = crypto.randomBytes(50000);
  const result1 = senderEncryptFile(pdfContent, 'application/pdf', 'document.pdf', recipientKP.publicKey);
  assert(result1.envelope && result1.envelope.encrypted, 'Encrypt PDF file');

  const decrypted1 = recipientDecryptFile(result1.envelope, recipientKP.privateKey);
  assert(Buffer.compare(decrypted1.fileBuffer, pdfContent) === 0, 'Decrypt PDF - content matches');
  assert(decrypted1.fileName === 'document.pdf', 'Decrypt PDF - filename recovered');

  const zipContent = crypto.randomBytes(8 * 1024 * 1024);
  const result2 = senderEncryptFile(zipContent, 'application/zip', 'archive.zip', recipientKP.publicKey);
  assert(result2.envelope.encrypted.chunkCount === 2, 'ZIP file split into 2 chunks (8 MB)');
  const decrypted2 = recipientDecryptFile(result2.envelope, recipientKP.privateKey);
  assert(Buffer.compare(decrypted2.fileBuffer, zipContent) === 0, 'Decrypt ZIP - content matches');
  assert(decrypted2.fileName === 'archive.zip', 'Decrypt ZIP - filename recovered');

  const txtContent = Buffer.from('Hello World');
  const result3 = senderEncryptFile(txtContent, 'text/plain', 'readme.txt', recipientKP.publicKey);
  const decrypted3 = recipientDecryptFile(result3.envelope, recipientKP.privateKey);
  assert(decrypted3.fileBuffer.toString() === 'Hello World', 'Text file round-trip');

  try { validateFile(crypto.randomBytes(10), 'application/exe', 'malware.exe'); assert(false, 'Block .exe files'); } catch { assert(true, 'Block .exe files'); }
  try { validateFile(crypto.randomBytes(10), 'application/pdf', 'script.bat'); assert(false, 'Block .bat files'); } catch { assert(true, 'Block .bat files'); }
  try { validateFile(Buffer.alloc(0), 'application/pdf', 'empty.pdf'); assert(false, 'Reject empty buffer'); } catch { assert(true, 'Reject empty buffer'); }
  try { validateFile(crypto.randomBytes(10), 'application/x-msdownload', 'test.dll'); assert(false, 'Reject unknown MIME'); } catch { assert(true, 'Reject unknown MIME'); }

  const wrongKP = generateFileKeyPair();
  try { recipientDecryptFile(result1.envelope, wrongKP.privateKey); assert(false, 'Wrong key decryption fails'); } catch { assert(true, 'Wrong key decryption fails'); }

  const tampered = JSON.parse(JSON.stringify(result1.envelope));
  tampered.metaHmac = crypto.randomBytes(32).toString('base64');
  try { recipientDecryptFile(tampered, recipientKP.privateKey); assert(false, 'Tampered HMAC rejected'); } catch { assert(true, 'Tampered HMAC rejected'); }

  assert(result1.envelope.encryptedFileName && result1.envelope.encryptedFileName.encryptedName, 'Filename is encrypted in envelope');

  console.log('\n2. Double Ratchet Protocol');

  const { sessionA, sessionB } = createSessionPair();

  const msg1 = sessionA.encrypt('Hello from A');
  sessionB.setRemoteDHKey(msg1.dhPublicKey);
  const pt1 = sessionB.decrypt(msg1);
  assert(pt1 === 'Hello from A', 'A -> B first message');

  sessionB.dhRatchetStep();
  const msg2 = sessionB.encrypt('Hello from B');
  sessionA.setRemoteDHKey(msg2.dhPublicKey);
  const pt2 = sessionA.decrypt(msg2);
  assert(pt2 === 'Hello from B', 'B -> A reply');

  const msg3 = sessionA.encrypt('Second from A');
  const pt3 = sessionB.decrypt(msg3);
  assert(pt3 === 'Second from A', 'A -> B second message after ratchet');

  for (let i = 0; i < 10; i++) {
    const m = sessionA.encrypt('Burst ' + i);
    const p = sessionB.decrypt(m);
    assert(p === 'Burst ' + i, 'Burst message ' + i);
  }

  const stateA = sessionA.getState();
  const stateB = sessionB.getState();
  assert(stateA.sendCounter > 0, 'Send counter advances');
  assert(stateB.recvCounter > 0, 'Recv counter advances');

  const idA = generateIdentityKeyPair();
  const idB = generateIdentityKeyPair();
  const ephA = generateEphemeralKeyPair();
  const spkB = generateEphemeralKeyPair();
  const otpB = generateEphemeralKeyPair();
  const keysA = x3dhInitiator(idA, ephA, { publicKey: idB.publicKey }, { publicKey: spkB.publicKey }, { publicKey: otpB.publicKey });
  const keysB = x3dhResponder(idB, spkB, idA.publicKey, ephA.publicKey, otpB);
  assert(Buffer.compare(keysA.rootKey, keysB.rootKey) === 0, 'X3DH root keys match');
  assert(Buffer.compare(keysA.chainKey, keysB.chainKey) === 0, 'X3DH chain keys match');

  const keysNoOTP_A = x3dhInitiator(idA, ephA, { publicKey: idB.publicKey }, { publicKey: spkB.publicKey }, null);
  const keysNoOTP_B = x3dhResponder(idB, spkB, idA.publicKey, ephA.publicKey, null);
  assert(Buffer.compare(keysNoOTP_A.rootKey, keysNoOTP_B.rootKey) === 0, 'X3DH without OTP keys match');

  const chainKey = crypto.randomBytes(32);
  const { messageKey: mk1, nextChainKey: ck1 } = kdfChainKey(chainKey);
  const { messageKey: mk2, nextChainKey: ck2 } = kdfChainKey(chainKey);
  assert(Buffer.compare(mk1, mk2) === 0, 'KDF chain deterministic');
  assert(Buffer.compare(ck1, ck2) === 0, 'KDF chain key deterministic');
  assert(Buffer.compare(mk1, ck1) !== 0, 'Message key differs from chain key');

  const testMK = crypto.randomBytes(32);
  const enc = encryptMessage(testMK, 'test payload', 'aad');
  const dec = decryptMessage(testMK, enc, 'aad');
  assert(dec === 'test payload', 'Encrypt/decrypt with AAD');

  try { decryptMessage(crypto.randomBytes(32), enc, 'aad'); assert(false, 'Wrong message key fails'); } catch { assert(true, 'Wrong message key fails'); }
  try { decryptMessage(testMK, enc, 'wrong-aad'); assert(false, 'Wrong AAD fails'); } catch { assert(true, 'Wrong AAD fails'); }

  console.log('\n3. Anti-Bot Systems');

  const pow = new ProofOfWork(2);
  const challenge = pow.generateChallenge();
  assert(challenge.challenge && challenge.difficulty === 2, 'PoW challenge generated');

  let nonce = 0;
  let hash;
  while (true) {
    hash = crypto.createHash('sha256').update(challenge.challenge + nonce).digest('hex');
    if (hash.startsWith('00')) break;
    nonce++;
  }
  const powResult = pow.verifyProof(challenge.challenge, String(nonce));
  assert(powResult.valid === true, 'PoW valid proof accepted');

  const powResult2 = pow.verifyProof(challenge.challenge, String(nonce));
  assert(powResult2.valid === false && powResult2.reason === 'already_used', 'PoW replay rejected');

  const powResult3 = pow.verifyProof(challenge.challenge + 'x', '0');
  assert(powResult3.valid === false && powResult3.reason === 'unknown_challenge', 'PoW unknown challenge rejected');

  const powResult4 = pow.verifyProof(pow.generateChallenge().challenge, '0');
  assert(powResult4.valid === false, 'PoW wrong nonce rejected');

  const fpThrottle = new FingerprintThrottle();
  for (let i = 0; i < 20; i++) {
    fpThrottle.check('test-fp');
  }
  const throttleResult = fpThrottle.check('test-fp');
  assert(throttleResult.allowed === false, 'Fingerprint throttle blocks after limit');
  assert(fpThrottle.check('other-fp').allowed === true, 'Different fingerprint not blocked');

  const turnstile = new TurnstileVerifier('test-secret-key');
  const noTokenResult = await turnstile.verify(null, '1.2.3.4');
  assert(noTokenResult.success === false && noTokenResult.reason === 'missing_token', 'Turnstile rejects missing token');

  const longToken = 'a'.repeat(3000);
  const longResult = await turnstile.verify(longToken, '1.2.3.4');
  assert(longResult.success === false && longResult.reason === 'token_too_long', 'Turnstile rejects oversized token');

  pow.destroy();
  fpThrottle.destroy();
  turnstile.destroy();

  console.log('\n4. Blind Server');

  const blindStore = new BlindEnvelopeStore();
  const bucket = blindStore.generateBucket();
  assert(bucket.length === 32, 'Bucket ID is 32 hex chars');

  const testBlob = crypto.randomBytes(1000).toString('base64');
  const storeResult = blindStore.put(bucket, 'env-001', testBlob);
  assert(storeResult.stored === true, 'Blind store accepts envelope');

  const retrieved = blindStore.get(bucket, 'env-001');
  assert(retrieved && retrieved.blob === testBlob, 'Blind retrieve returns original blob');

  assert(blindStore.get(bucket, 'env-999') === null, 'Unknown envelope returns null');
  assert(blindStore.get('bad-bucket', 'env-001') === null, 'Wrong bucket returns null');

  blindStore.remove(bucket, 'env-001');
  assert(blindStore.get(bucket, 'env-001') === null, 'Blob removed after delete');

  const stripper = new MetadataStripper();
  const fakeReq = { headers: { 'x-forwarded-for': '1.2.3.4', 'user-agent': 'Firefox', 'referer': 'http://evil.com' } };
  const stripped = stripper.strip(fakeReq);
  assert(stripped.requestId && stripped.timestamp, 'Metadata stripped to requestId + timestamp only');
  assert(!stripped['x-forwarded-for'] && !stripped['user-agent'], 'No IP or UA in stripped metadata');

  const sealedSender = new SealedSender();
  const serverPub = sealedSender.getServerPublicKey();
  assert(Buffer.isBuffer(serverPub) && serverPub.length > 0, 'Sealed sender has server public key');

  const sealed = sealedSender.seal('alice', 'bucket-bob', 'encrypted-payload-here');
  assert(sealed.ephemeralPub && sealed.ciphertext && sealed.iv && sealed.tag, 'Sealed message has all fields');

  const unsealed = sealedSender.unseal(sealed);
  assert(unsealed.sender === 'alice', 'Unsealed sender identity recovered');
  assert(unsealed.bucket === 'bucket-bob', 'Unsealed bucket recovered');
  assert(unsealed.payload === 'encrypted-payload-here', 'Unsealed payload recovered');

  const delivery = new UnlinkableDelivery(blindStore);
  const bucket2 = blindStore.generateBucket();
  await delivery.deliver(bucket2, 'msg-1', 'test-data');
  const fetched = await delivery.retrieve(bucket2, 'msg-1');
  assert(fetched && fetched.blob === 'test-data', 'Unlinkable delivery round-trip');

  blindStore.destroy();

  console.log('\n5. Snowflake Traffic Obfuscation');

  const snowflake = new SnowflakeProxy();
  assert(snowflake.isEnabled() === false, 'Snowflake starts disabled');

  const enableResult = snowflake.enable();
  assert(enableResult.status === 'enabled', 'Snowflake enable returns status');
  assert(snowflake.isEnabled() === true, 'Snowflake is enabled');

  const peer1 = snowflake.simulatePeerConnection();
  assert(peer1.peerId && peer1.sdpOffer && peer1.iceCandidate, 'Peer connection has SDP + ICE');
  assert(peer1.sdpOffer.includes('webrtc-datachannel'), 'SDP contains datachannel');
  assert(peer1.iceCandidate.candidate.includes('srflx'), 'ICE candidate is server-reflexive');

  const relayResult = snowflake.simulateRelay(peer1.peerId, 'test data packet');
  assert(relayResult.relayed === true, 'Data relayed through peer');
  assert(relayResult.shapedSize >= relayResult.originalSize, 'Shaped size >= original size');

  const peer2 = snowflake.simulatePeerConnection();
  const stats = snowflake.getStats();
  assert(stats.activePeers === 2, 'Two active peers');
  assert(stats.totalRelayed > 0, 'Relay count tracked');

  const dcResult = snowflake.disconnectPeer(peer1.peerId);
  assert(dcResult.disconnected === true, 'Peer disconnected');
  assert(snowflake.getStats().activePeers === 1, 'Peer count decremented');

  snowflake.disconnectPeer(peer2.peerId);

  const shaper = new TrafficShaper();

  shaper.setPattern('video-call');
  const shaped1 = shaper.shape(Buffer.from('small'));
  assert(shaped1.length > 5, 'Video-call pattern pads small data');

  shaper.setPattern('social-scroll');
  const shaped2 = shaper.shape(Buffer.from('test'));
  assert(shaped2.length > 4, 'Social-scroll pattern pads data');

  const original = Buffer.from('extract me');
  shaper.setPattern('browsing');
  const shaped3 = shaper.shape(original);
  const unshaped3 = shaper.unshape(shaped3);
  assert(Buffer.compare(unshaped3, original) === 0, 'Traffic unshape recovers original data');

  assert(shaper.getPatterns().length === 3, 'Three traffic patterns available');

  const fronting = new DomainFronting();
  const front = fronting.selectFront();
  assert(front.connectTo && front.hostHeader, 'Domain fronting selects front + host');
  assert(front.connectTo !== front.hostHeader, 'Front domain differs from real host');

  const headers = fronting.buildHeaders({ test: true });
  assert(headers['Host'] && headers['Content-Type'], 'Domain fronting builds proper headers');

  const disableResult = snowflake.disable();
  assert(disableResult.status === 'disabled', 'Snowflake disabled');
  assert(snowflake.getStats().activePeers === 0, 'All peers cleared on disable');

  console.log('\n6. Cross-Module Integration');

  const { sessionA: drA, sessionB: drB } = createSessionPair();
  const fileData = crypto.randomBytes(10000);
  const fileKP = generateFileKeyPair();
  const fileEnv = senderEncryptFile(fileData, 'application/pdf', 'secret.pdf', fileKP.publicKey);
  const envJson = JSON.stringify(fileEnv.envelope);
  const drMsg = drA.encrypt(envJson);
  drB.setRemoteDHKey(drMsg.dhPublicKey);
  const drPlain = drB.decrypt(drMsg);
  const recoveredEnv = JSON.parse(drPlain);
  const recoveredFile = recipientDecryptFile(recoveredEnv, fileKP.privateKey);
  assert(Buffer.compare(recoveredFile.fileBuffer, fileData) === 0, 'File encrypted through Double Ratchet channel');
  assert(recoveredFile.fileName === 'secret.pdf', 'Filename survives Double Ratchet');

  const blindStore2 = new BlindEnvelopeStore();
  const bkt = blindStore2.generateBucket();
  blindStore2.put(bkt, 'file-001', envJson);
  const blindRetrieved = blindStore2.get(bkt, 'file-001');
  const blindDecrypted = recipientDecryptFile(JSON.parse(blindRetrieved.blob), fileKP.privateKey);
  assert(Buffer.compare(blindDecrypted.fileBuffer, fileData) === 0, 'File through blind server store');
  blindStore2.destroy();

  const sealedSender2 = new SealedSender();
  const sealedFile = sealedSender2.seal('sender-x', 'bucket-y', envJson);
  const unsealedFile = sealedSender2.unseal(sealedFile);
  const sealedDecrypted = recipientDecryptFile(JSON.parse(unsealedFile.payload), fileKP.privateKey);
  assert(Buffer.compare(sealedDecrypted.fileBuffer, fileData) === 0, 'File through sealed sender');

  console.log('\n=== Results: ' + passed + ' passed, ' + failed + ' failed ===');
  if (errors.length > 0) {
    console.log('Failed tests:');
    errors.forEach(e => console.log('  - ' + e));
  }
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});

// ═══════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════
const S = {
  myId: null,
  myECDHKeyPair: null,      // ECDH pour dérivation de clé
  mySignKeyPair: null,      // ECDSA pour signatures
  myPubKeyB64: null,        // ECDH pub key
  mySignPubKeyB64: null,    // ECDSA pub key
  myFingerprint: null,
  idExpiresAt: 0,
  idTimerInterval: null,
  clockOffset: 0,
  activePair: null,         // { peerId, peerPubKey, sharedKey, peerSignPubKey, fpVerified }
  pendingPairing: null,
  pollHandle: null,
  messages: [],
  msgTimerHandle: null,
  seenNonces: new Set(),    // ← anti-replay: nonces déjà vus (+ persistant en localStorage)
  captchaAnswer: '',
  notifTimeout: null,
};

// Charger nonces persistants au démarrage
function loadPersistedNonces() {
  try {
    const stored = localStorage.getItem('nexus_seen_nonces');
    if (stored) {
      const arr = JSON.parse(stored);
      S.seenNonces = new Set(arr);
    }
  } catch(e) { /* ignore */ }
}

// Sauvegarder nonces après chaque ajout
function persistNonces() {
  try {
    localStorage.setItem('nexus_seen_nonces', JSON.stringify([...S.seenNonces]));
  } catch(e) { /* ignore */ }
}

const ID_DURATION  = 10 * 60 * 1000;
const MSG_TTL      = 2 * 60 * 1000;
const POLL_MS      = 2000;
const MAX_NONCES   = 2000; // limite taille du Set anti-replay

// ═══════════════════════════════════════════════════════════
//  UTILS
// ═══════════════════════════════════════════════════════════
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function genId(len = 28) {
  const buf = new Uint8Array(len * 3);
  crypto.getRandomValues(buf);
  let out = '';
  for (let i = 0; i < buf.length && out.length < len; i++) {
    // Pas de biais : on rejette les valeurs >= floor(256/58)*58
    if (buf[i] < 232) out += B58[buf[i] % 58];
  }
  // Fallback si pas assez
  while (out.length < len) {
    const tmp = new Uint8Array(8);
    crypto.getRandomValues(tmp);
    for (const b of tmp) {
      if (b < 232 && out.length < len) out += B58[b % 58];
    }
  }
  return out;
}

function now() { return Date.now() + S.clockOffset; }

function escapeHtml(t) {
  return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
          .replace(/"/g,'&quot;').replace(/\n/g,'<br>');
}

function handleMsgKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 110) + 'px';
}

// ═══════════════════════════════════════════════════════════
//  CRYPTO — ECDH (chiffrement) + ECDSA (signatures)
// ═══════════════════════════════════════════════════════════
async function generateECDHKeyPair() {
  return await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
  );
}

async function generateSignKeyPair() {
  return await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
}

async function exportPubKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

async function importECDHPubKey(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return await crypto.subtle.importKey('raw', raw, { name:'ECDH', namedCurve:'P-256' }, true, []);
}

async function importECDSAPubKey(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return await crypto.subtle.importKey(
    'raw', raw, { name:'ECDSA', namedCurve:'P-256' }, true, ['verify']
  );
}

async function deriveSharedKey(privateKey, peerPubKey) {
  return await crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPubKey },
    privateKey,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptMsg(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)
  );
  return {
    iv: btoa(String.fromCharCode(...iv)),
    ct: btoa(String.fromCharCode(...new Uint8Array(ct)))
  };
}

async function decryptMsg(key, ivB64, ctB64) {
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}

// Signe un objet avec la clé ECDSA
// Utilise sérialisation canonique (clés triées) pour garantir déterminisme
async function signData(signingKey, dataObj) {
  // Sérialisation canonique : clés triées, format déterministe
  const canonicalStr = JSON.stringify(dataObj, Object.keys(dataObj).sort());
  const bytes = new TextEncoder().encode(canonicalStr);
  const sig = await crypto.subtle.sign(
    { name:'ECDSA', hash:'SHA-256' }, signingKey, bytes
  );
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

// Vérifie une signature ECDSA avec sérialisation canonique
async function verifySignature(verifyKey, dataObj, sigB64) {
  try {
    const sig = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    // Sérialisation canonique identique à signData
    const canonicalStr = JSON.stringify(dataObj, Object.keys(dataObj).sort());
    const bytes = new TextEncoder().encode(canonicalStr);
    return await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, verifyKey, sig, bytes);
  } catch(e) { return false; }
}

async function keyFingerprint(pubKeyB64) {
  const data = new TextEncoder().encode(pubKeyB64);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2,'0'))
    .join('').match(/.{4}/g).join(' ').slice(0,47);
}

// ═══════════════════════════════════════════════════════════
//  STORAGE (via API REST)
// ═══════════════════════════════════════════════════════════
async function store(key, val, shared=true) {
  try {
    const response = await fetch(`/api/storage/${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: JSON.stringify(val), shared })
    });
    return response.ok;
  } catch(e) { return false; }
}

async function load(key, shared=true) {
  try {
    const response = await fetch(`/api/storage/${encodeURIComponent(key)}`);
    if (!response.ok) return null;
    const data = await response.json();
    return data.value ? JSON.parse(data.value) : null;
  } catch(e) { return null; }
}

async function del(key, shared=true) {
  try {
    await fetch(`/api/storage/${encodeURIComponent(key)}`, { method: 'DELETE' });
  } catch(e) { /* ignore */ }
}

async function listKeys(prefix, shared=true) {
  try {
    const response = await fetch(`/api/storage/list/${encodeURIComponent(prefix)}`);
    if (!response.ok) return [];
    const data = await response.json();
    return data.keys || [];
  } catch(e) { return []; }
}

// ═══════════════════════════════════════════════════════════
//  CLOCK SYNC (avec fallback)
// ═══════════════════════════════════════════════════════════
async function syncClock() {
  try {
    const t0 = Date.now();
    const r = await fetch('https://worldtimeapi.org/api/timezone/Etc/UTC',
      { signal: AbortSignal.timeout(4000) });
    const data = await r.json();
    const t1 = Date.now();
    S.clockOffset = new Date(data.datetime).getTime() + (t1-t0)/2 - t1;
    const abs = Math.abs(S.clockOffset);
    const clockWarn = document.getElementById('clock-warn');
    const syncStatus = document.getElementById('sync-status');
    
    if (abs > 30000) {
      if (clockWarn) clockWarn.style.display = 'block';
      if (syncStatus) {
        syncStatus.style.color = 'var(--warning)';
        syncStatus.textContent = `[WARN] Offset ${Math.round(S.clockOffset/1000)}s`;
      }
    } else {
      if (syncStatus) {
        syncStatus.style.color = 'var(--success)';
        syncStatus.textContent = 'NTP sync OK';
      }
    }
  } catch(e) {
    S.clockOffset = 0;
    const syncStatus = document.getElementById('sync-status');
    if (syncStatus) {
      syncStatus.style.color = 'var(--text-3)';
      syncStatus.textContent = 'NTP offline (local clock)';
    }
    /* NTP sync failed */
  }
}

function updateClock() {
  const d = new Date(now());
  const hdrTime = document.getElementById('hdr-time');
  if (hdrTime) hdrTime.textContent = d.toISOString().slice(11,19) + ' UTC';
}
setInterval(updateClock, 1000);

// ═══════════════════════════════════════════════════════════
//  CAPTCHA (côté client — note : bypass possible via console,
//  pas de sécurité réelle. Sert uniquement de friction basique.)
// ═══════════════════════════════════════════════════════════
function drawCaptcha() {
  const canvas = document.getElementById('captcha-canvas');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0,0,260,70);
  ctx.fillStyle = '#f0efe9'; ctx.fillRect(0,0,260,70);

  for (let i=0;i<300;i++) {
    ctx.fillStyle = `rgba(100,100,100,${Math.random()*.15})`;
    ctx.fillRect(Math.random()*260, Math.random()*70, 1, 1);
  }
  for (let i=0;i<4;i++) {
    ctx.strokeStyle = `rgba(26,86,232,${Math.random()*.15})`;
    ctx.lineWidth = Math.random();
    ctx.beginPath();
    ctx.moveTo(0, Math.random()*70);
    ctx.bezierCurveTo(65, Math.random()*70, 195, Math.random()*70, 260, Math.random()*70);
    ctx.stroke();
  }

  const a = Math.floor(Math.random()*18)+3;
  const b = Math.floor(Math.random()*12)+2;
  const add = Math.random() > .5;
  S.captchaAnswer = String(add ? a+b : Math.max(a,b)-Math.min(a,b));
  const label = `${Math.max(a,b)} ${add ? '+' : '−'} ${add ? b : Math.min(a,b)} = ?`;

  ctx.font = '600 24px JetBrains Mono, monospace';
  ctx.fillStyle = '#1a1a1a'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.save(); ctx.translate(130,35);
  ctx.rotate((Math.random()-.5)*.05); ctx.fillText(label,0,0);
  ctx.restore();

  document.getElementById('cap-input').value = '';
  document.getElementById('cap-err').textContent = '';
}

function verifyCaptcha() {
  // Note : bypass trivial via console — pas de sécurité réelle
  const val = document.getElementById('cap-input').value.trim();
  if (val === S.captchaAnswer) {
    const captcha = document.getElementById('captcha');
    const app = document.getElementById('app');
    if (captcha) captcha.style.display = 'none';
    if (app) app.style.display = 'flex';
    renderIdentity();
    S.idTimerInterval = setInterval(tickIdTimer, 1000);
    setTimeout(() => rotateId(), S.idExpiresAt - now());
    S.pollHandle = setInterval(poll, POLL_MS);
    S.msgTimerHandle = setInterval(updateMessageTimers, 1000);
    notify('Bienvenue sur NEXUS·SECURE v2.');
  } else {
    const capErr = document.getElementById('cap-err');
    if (capErr) capErr.textContent = 'Réponse incorrecte.';
    drawCaptcha();
    const inp = document.getElementById('cap-input');
    if (inp) {
      inp.style.borderColor = 'var(--error)';
      setTimeout(() => inp.style.borderColor = '', 800);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('cap-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') verifyCaptcha();
  });
});

// ═══════════════════════════════════════════════════════════
//  IDENTITY
// ═══════════════════════════════════════════════════════════
async function initIdentity() {
  if (S.idTimerInterval) clearInterval(S.idTimerInterval);

  S.myId = genId(28);
  S.myECDHKeyPair = await generateECDHKeyPair();
  S.mySignKeyPair = await generateSignKeyPair();
  S.myPubKeyB64 = await exportPubKey(S.myECDHKeyPair.publicKey);
  S.mySignPubKeyB64 = await exportPubKey(S.mySignKeyPair.publicKey);
  S.myFingerprint = await keyFingerprint(S.myPubKeyB64 + S.mySignPubKeyB64);
  S.idExpiresAt = now() + ID_DURATION;

  await store(`user:${S.myId}`, {
    pubKey: S.myPubKeyB64,
    signPubKey: S.mySignPubKeyB64,
    createdAt: now(),
    fp: S.myFingerprint
  });

  S.idTimerInterval = setInterval(tickIdTimer, 1000);
  setTimeout(() => rotateId(), ID_DURATION);
  renderIdentity();
}

function renderIdentity() {
  const el = document.getElementById('my-id-text');
  if (!el) return;
  el.textContent = S.myId.match(/.{1,7}/g).join('  ');
  const fpEl = document.getElementById('fp-text');
  fpEl.textContent = S.myFingerprint;
  fpEl.style.cursor = 'pointer';
  fpEl.onclick = copyFingerprint;
}

function tickIdTimer() {
  const remaining = Math.max(0, S.idExpiresAt - now());
  const pct = (remaining / ID_DURATION) * 100;
  const m = String(Math.floor(remaining/60000)).padStart(2,'0');
  const s = String(Math.floor((remaining%60000)/1000)).padStart(2,'0');
  document.getElementById('id-ttl-val').textContent = `${m}:${s}`;
  const bar = document.getElementById('id-ttl-bar');
  bar.style.width = pct + '%';
  bar.style.background = pct < 15 ? 'var(--red)' : pct < 30 ? 'var(--amber)' : 'var(--accent)';
}

async function rotateId() {
  await del(`user:${S.myId}`);
  if (S.activePair) { addSysMsg('Votre ID a expiré. Canal fermé.', 'er'); disconnect(true); }
  await initIdentity();
  notify('ID rotatif régénéré automatiquement.', 'warn');
}

async function resetId() {
  if (!confirm('Réinitialiser votre ID maintenant ? Le canal actif sera rompu.')) return;
  await rotateId();
}

async function copyMyId() {
  if (!S.myId) return;
  try {
    await navigator.clipboard.writeText(S.myId);
    const box = document.getElementById('my-id-box');
    const tip = document.createElement('div');
    tip.className = 'tooltip-copied'; tip.textContent = 'Copié !';
    box.style.position = 'relative'; box.appendChild(tip);
    setTimeout(() => tip.remove(), 1200);
  } catch(e) { prompt('Votre ID :', S.myId); }
}

async function copyFingerprint() {
  if (!S.myFingerprint) return;
  try {
    await navigator.clipboard.writeText(S.myFingerprint);
    notify('Empreinte copiée — partagez hors-bande pour vérification anti-MITM.');
  } catch(e) {}
}

function checkPeerFp() {
  if (!S.activePair) return;
  const val = document.getElementById('fp-peer-verify').value.trim();
  const el = document.getElementById('fp-verify-result');
  if (!val) { el.textContent = ''; return; }
  if (val === S.activePair.peerFp) {
    el.textContent = '[OK] Empreinte confirmée - pas de MITM détecté';
    el.className = 'fp-verify-result fp-ok';
    S.activePair.fpVerified = true;
    document.getElementById('fp-warning').classList.add('hidden');
  } else {
    el.textContent = '[WARN] Empreinte incorrecte - possible MITM !';
    el.className = 'fp-verify-result fp-bad';
    S.activePair.fpVerified = false;
  }
}

// ═══════════════════════════════════════════════════════════
//  PAIRING
// ═══════════════════════════════════════════════════════════
async function sendPairingRequest() {
  const input = document.getElementById('peer-id-input');
  let peerId = input.value;
  
  // SÉCURITÉ: Nettoyer TOUS les whitespace (espaces, retours à la ligne, tabs, etc.)
  peerId = peerId.replace(/\s/g, '');
  
  if (peerId.length !== 28) { 
    notify(`ID invalide: ${peerId.length} caractères trouvés (28 requis). Retirer les espaces/retours à la ligne.`, 'err'); 
    return; 
  }
  
  // Validation base58 simple
  const validB58 = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{28}$/.test(peerId);
  if (!validB58) { 
    notify('ID invalide: caractères non reconnus.', 'err'); 
    return; 
  }
  
  if (peerId === S.myId) { notify('Impossible de s\'appairer avec soi-même.', 'err'); return; }

  const peerData = await load(`user:${peerId}`);
  if (!peerData) { 
    notify('Identifiant introuvable ou expiré.', 'err'); 
    return; 
  }

  // Créer la requête et la signer
  const reqPayload = {
    fromId: S.myId,
    fromPubKey: S.myPubKeyB64,
    fromSignPubKey: S.mySignPubKeyB64,
    fromFp: S.myFingerprint,
    sentAt: now(),
    nonce: genId(16),
  };
  const sig = await signData(S.mySignKeyPair.privateKey, reqPayload);

  const storeKey = `pair-req:${peerId}:${S.myId}`;
  await store(storeKey, { ...reqPayload, sig });

  const peerIdDisplay = document.getElementById('sidebar-peer-id');
  if (peerIdDisplay) peerIdDisplay.textContent = peerId.match(/.{1,7}/g).join('  ');
  const peerStatus = document.getElementById('peer-status');
  if (peerStatus) {
    peerStatus.textContent = 'Demande envoyée…';
    peerStatus.className = 'peer-status';
  }
  
  const chatPeerId = document.getElementById('chat-peer-id');
  if (chatPeerId) chatPeerId.textContent = peerId.match(/.{1,7}/g).join('  ');
}

async function checkIncomingPairings() {
  if (S.activePair) return;
  const prefix = `pair-req:${S.myId}:`;
  const keys = await listKeys(prefix);
  
  for (const k of keys) {
    const req = await load(k);
    if (!req) {
      continue;
    }
    if (now() - req.sentAt > 5*60*1000) { await del(k); continue; }

      // Vérifier la signature de la requête d'appareillage
    const { sig, ...payload } = req;
    let sigValid = false;
    try {
      const signerKey = await importECDSAPubKey(req.fromSignPubKey);
      sigValid = await verifySignature(signerKey, payload, sig);
    } catch(e) {
      // Signature verification failed
    }

    if (!sigValid) {
      addSysMsg('Demande d\'appareillage avec signature invalide rejetée.', 'er');
      await del(k);
      continue;
    }

    S.pendingPairing = { key: k, ...req };
    document.getElementById('pop-from-id').textContent = req.fromId.match(/.{1,7}/g).join('  ');
    document.getElementById('pop-fp-val').textContent = req.fromFp || '(non disponible)';
    document.getElementById('pop-fp-confirm').value = '';
    document.getElementById('pop-fp-warn').textContent = '';
    document.getElementById('overlay').className = 'on';
    return;
  }
}

document.getElementById('pop-fp-confirm').addEventListener('input', function() {
  if (!S.pendingPairing) return;
  const val = this.value.trim();
  const el = document.getElementById('pop-fp-warn');
  if (!val) { el.textContent = ''; return; }
  if (val === S.pendingPairing.fromFp) {
    el.textContent = '[OK] Empreinte confirmée';
    el.style.color = 'var(--green)';
  } else {
    el.textContent = '[FAIL] Empreinte différente — risque MITM !';
    el.style.color = 'var(--red)';
  }
});

async function acceptPairing() {
  if (!S.pendingPairing) return;
  document.getElementById('overlay').className = '';

  const { fromId, fromPubKey, fromSignPubKey, fromFp, key } = S.pendingPairing;

  const respPayload = {
    accepted: true,
    fromId: S.myId,
    toPubKey: S.myPubKeyB64,
    toSignPubKey: S.mySignPubKeyB64,
    toFp: S.myFingerprint,
    at: now(),
    nonce: genId(16),
  };
  const sig = await signData(S.mySignKeyPair.privateKey, respPayload);
  await store(`pair-resp:${fromId}:${S.myId}`, { ...respPayload, sig });

  const peerECDHKey = await importECDHPubKey(fromPubKey);
  const shared = await deriveSharedKey(S.myECDHKeyPair.privateKey, peerECDHKey);
  const peerSignKey = await importECDSAPubKey(fromSignPubKey);

  const fpVerified = document.getElementById('pop-fp-confirm').value.trim() === fromFp;
  S.activePair = { peerId: fromId, peerPubKey: fromPubKey, sharedKey: shared, peerSignKey, peerFp: fromFp, fpVerified };

  await del(key);
  S.pendingPairing = null;
  activateChat(fromId, fpVerified);
  notify('Canal E2E établi. ECDH complété, signatures ECDSA actives.');
}

async function rejectPairing() {
  if (!S.pendingPairing) return;
  document.getElementById('overlay').className = '';
  const { key, fromId } = S.pendingPairing;
  await del(key);
  const respPayload = { accepted: false, at: now() };
  await store(`pair-resp:${fromId}:${S.myId}`, respPayload);
  S.pendingPairing = null;
  notify('Demande refusée.', 'warn');
}

async function checkPairingResponse() {
  if (S.activePair) return;
  const peerEl = document.getElementById('sidebar-peer-id');
  if (!peerEl || peerEl.textContent === 'Aucune connexion active') return;
  const peerId = peerEl.textContent.replace(/\s+/g,'');
  if (peerId.length !== 28) return;

  const keys = await listKeys(`pair-resp:${S.myId}:`);
  for (const k of keys) {
    const resp = await load(k);
    if (!resp) continue;
    if (!resp.accepted) {
      notify('Demande refusée par le pair.', 'err');
      const sbPeerId = document.getElementById('sidebar-peer-id');
      if (sbPeerId) sbPeerId.textContent = 'Aucune connexion active';
      const peerStatus = document.getElementById('peer-status');
      if (peerStatus) {
        peerStatus.textContent = 'En attente d\'appareillage';
        peerStatus.className = 'peer-status none';
      }
      await del(k); return;
    }

    // Vérifier la signature de la réponse
    const { sig, ...payload } = resp;
    let sigValid = false;
    try {
      const signerKey = await importECDSAPubKey(resp.toSignPubKey);
      sigValid = await verifySignature(signerKey, payload, sig);
    } catch(e) {}

    if (!sigValid) {
      notify('Réponse d\'appareillage avec signature invalide !', 'err');
      await del(k); return;
    }

    const peerECDHKey = await importECDHPubKey(resp.toPubKey);
    const shared = await deriveSharedKey(S.myECDHKeyPair.privateKey, peerECDHKey);
    const peerSignKey = await importECDSAPubKey(resp.toSignPubKey);
    const actualPeerId = k.replace(`pair-resp:${S.myId}:`, '');

    S.activePair = {
      peerId: actualPeerId, peerPubKey: resp.toPubKey,
      sharedKey: shared, peerSignKey, peerFp: resp.toFp, fpVerified: false
    };
    await del(k);
    activateChat(actualPeerId, false);
    notify('Appareillage accepté ! Canal E2E + ECDSA actif.');
    return;
  }
}

function activateChat(peerId, fpVerified) {
  const display = peerId.match(/.{1,7}/g).join('  ');
  const chatPeerId = document.getElementById('chat-peer-id');
  if (chatPeerId) chatPeerId.textContent = display;
  const peerStatus = document.getElementById('peer-status');
  if (peerStatus) {
    peerStatus.textContent = 'Canal chiffré actif';
    peerStatus.className = 'peer-status';
  }
  const disc = document.getElementById('disc-btn');
  if (disc) disc.style.display = 'inline-block';
  const msgInp = document.getElementById('msg-inp');
  if (msgInp) msgInp.disabled = false;
  const btnSend = document.getElementById('btn-send');
  if (btnSend) btnSend.disabled = false;
  const noPeerView = document.getElementById('no-peer-view');
  if (noPeerView) noPeerView.style.display = 'none';

  if (!fpVerified) {
    const fpWarning = document.getElementById('fp-warning');
    if (fpWarning) fpWarning.classList.remove('hidden');
  }

  addSysMsg('Canal E2E établi. AES-256-GCM + signatures ECDSA actives.', 'ev');
  syncClock();
}

function disconnect(silent=false) {
  if (!silent) addSysMsg('Canal sécurisé fermé.', 'er');
  S.activePair = null;
  const chatPeerId = document.getElementById('chat-peer-id');
  if (chatPeerId) chatPeerId.textContent = 'Aucune connexion active';
  const sbPeerId = document.getElementById('sidebar-peer-id');
  if (sbPeerId) sbPeerId.textContent = 'Aucune connexion active';
  const peerStatus = document.getElementById('peer-status');
  if (peerStatus) {
    peerStatus.textContent = 'En attente d\'appareillage';
    peerStatus.className = 'peer-status none';
  }
  const disc = document.getElementById('disc-btn');
  if (disc) disc.style.display = 'none';
  const msgInp = document.getElementById('msg-inp');
  if (msgInp) msgInp.disabled = true;
  const btnSend = document.getElementById('btn-send');
  if (btnSend) btnSend.disabled = true;
  const fpWarning = document.getElementById('fp-warning');
  if (fpWarning) fpWarning.classList.add('hidden');
  document.getElementById('fp-verify-result').textContent = '';
  if (!document.getElementById('msgs').querySelector('.msg'))
    document.getElementById('no-peer-view').style.display = 'flex';
}

// ═══════════════════════════════════════════════════════════
//  MESSAGING — avec signatures ECDSA + anti-replay
// ═══════════════════════════════════════════════════════════
function convId(a, b) { return [a,b].sort().join(':'); }

async function sendMessage() {
  if (!S.activePair) return;
  
  // SÉCURITÉ: fingerprint vérifié obligatoire
  if (!S.activePair.fpVerified) {
    notify('Empreinte non vérifiée. Vérifiez d\'abord avant d\'envoyer.', 'err');
    document.getElementById('fp-peer-verify').focus();
    return;
  }
  
  const inp = document.getElementById('msg-inp');
  const text = inp.value.trim();
  if (!text) return;
  inp.value = ''; inp.style.height = '';

  const { ct, iv } = await encryptMsg(S.activePair.sharedKey, text);
  const msgId = genId(16);
  const sentAt = now();
  const expiresAt = sentAt + MSG_TTL;
  const nonce = genId(20); // nonce unique anti-replay

  // Liaison cryptographique: conversation + destinataire explicite
  const cid = convId(S.myId, S.activePair.peerId);
  const sigPayload = {
    cid,               // Contexte de conversation
    from: S.myId,
    to: S.activePair.peerId,
    ct,
    iv,
    sentAt,
    expiresAt,
    nonce
  };
  const sig = await signData(S.mySignKeyPair.privateKey, sigPayload);

  await store(`msg:${cid}:${msgId}`, { ...sigPayload, sig });

  renderMessage({ id: msgId, text, dir: 'out', expiresAt, sentAt, sigValid: true });
  setTimeout(() => del(`msg:${cid}:${msgId}`), MSG_TTL + 5000);
}

async function pollMessages() {
  if (!S.activePair) return;
  const cid = convId(S.myId, S.activePair.peerId);
  const keys = await listKeys(`msg:${cid}:`);
  const t = now();

  for (const k of keys) {
    const msgId = k.replace(`msg:${cid}:`, '');
    if (S.messages.find(m => m.id === msgId)) continue;
    const data = await load(k);
    if (!data) continue;
    if (data.from === S.myId) continue;

    // ── Anti-replay : vérifier nonce ──
    if (S.seenNonces.has(data.nonce)) {
      addSysMsg('Message rejoué détecté et ignoré (anti-replay).', 'er');
      await del(k); continue;
    }

    // TTL check
    if (t > data.expiresAt) { await del(k); continue; }

    // Vérification TTL signé : expiresAt doit être dans la plage raisonnable
    const ttlRange = data.expiresAt - data.sentAt;
    if (ttlRange > MSG_TTL * 2 || ttlRange < 0) {
      addSysMsg('TTL de message suspect, ignoré.', 'er');
      await del(k); continue;
    }

    // SÉCURITÉ: Liaison cryptographique - vérifier contexte et destinataire
    if (!data.cid || data.cid !== cid) {
      addSysMsg('Message rejeté : contexte de conversation invalide.', 'er');
      await del(k); continue;
    }
    if (data.to !== S.myId) {
      addSysMsg('Message rejeté : pas destinataire du message.', 'er');
      await del(k); continue;
    }

    // ── Vérification signature ECDSA ──
    const { sig, ...payload } = data;
    let sigValid = false;
    try {
      sigValid = await verifySignature(S.activePair.peerSignKey, payload, sig);
    } catch(e) {}

    if (!sigValid) {
      addSysMsg('Message avec signature invalide rejeté (possible injection).', 'er');
      await del(k); continue;
    }

    // Ajouter le nonce au store anti-replay ET persister
    S.seenNonces.add(data.nonce);
    persistNonces();
    if (S.seenNonces.size > MAX_NONCES) {
      const first = S.seenNonces.values().next().value;
      S.seenNonces.delete(first);
      persistNonces();
    }

    try {
      const plaintext = await decryptMsg(S.activePair.sharedKey, data.iv, data.ct);
      renderMessage({ id: msgId, text: plaintext, dir: 'inc', expiresAt: data.expiresAt, sentAt: data.sentAt, sigValid: true });
    } catch(e) {
      addSysMsg('Impossible de déchiffrer (clé invalide ou message corrompu).', 'er');
    }
  }
}

function renderMessage({ id, text, dir, expiresAt, sentAt, sigValid }) {
  S.messages.push({ id, dir, expiresAt });
  const container = document.getElementById('msgs');
  document.getElementById('no-peer-view').style.display = 'none';

  const el = document.createElement('div');
  el.className = `msg ${dir}`;
  el.id = `msg-${id}`;

  const remaining = Math.max(0, expiresAt - now());
  const pct = (remaining / MSG_TTL) * 100;
  const timeStr = new Date(sentAt).toLocaleTimeString('fr-FR', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
  const sigClass = sigValid ? 'ok' : 'fail';
  const sigLabel = sigValid ? 'SIGN OK' : 'SIGN FAIL';

  el.innerHTML = `
    <div class="msg-bubble">${escapeHtml(text)}</div>
    <div class="msg-meta">
      <span>${timeStr}</span>
      <div class="ttl-track"><div class="ttl-prog" id="ttl-${id}" style="width:${pct}%"></div></div>
      <span id="exp-${id}">—</span>
      <span class="msg-sig ${sigClass}">${sigLabel}</span>
    </div>
  `;

  container.appendChild(el);
  container.scrollTop = container.scrollHeight;
}

function updateMessageTimers() {
  const t = now();
  const toRemove = [];
  for (const msg of S.messages) {
    const remaining = Math.max(0, msg.expiresAt - t);
    const pct = (remaining / MSG_TTL) * 100;
    const bar = document.getElementById(`ttl-${msg.id}`);
    const expEl = document.getElementById(`exp-${msg.id}`);
    if (!bar) continue;
    bar.style.width = pct + '%';
    bar.className = 'ttl-prog' + (pct < 15 ? ' crit' : pct < 35 ? ' warn' : '');
    const secs = Math.ceil(remaining / 1000);
    if (secs <= 0) { toRemove.push(msg.id); }
    else if (secs < 60) { if (expEl) expEl.textContent = `${secs}s`; }
    else { const m=Math.floor(secs/60),s=secs%60; if (expEl) expEl.textContent = `${m}m${String(s).padStart(2,'0')}s`; }
  }
  for (const id of toRemove) {
    const el = document.getElementById(`msg-${id}`);
    if (el) { el.style.transition = 'opacity .3s'; el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }
    S.messages.splice(S.messages.findIndex(m => m.id===id), 1);
  }
}

// ═══════════════════════════════════════════════════════════
//  SYSTEM MESSAGES + NOTIFICATIONS
// ═══════════════════════════════════════════════════════════
function addSysMsg(text, type='') {
  const container = document.getElementById('msgs');
  document.getElementById('no-peer-view').style.display = 'none';
  const el = document.createElement('div');
  el.className = `sys-msg ${type}`;
  el.textContent = text;
  container.appendChild(el);
  container.scrollTop = container.scrollHeight;
}

function notify(msg, type='') {
  const el = document.getElementById('notification');
  if (!el) {
    /* notification element not found */
    return;
  }
  el.textContent = msg; el.className = `notif ${type}`; el.style.display = 'block';
  if (S.notifTimeout) clearTimeout(S.notifTimeout);
  S.notifTimeout = setTimeout(() => { el.style.display = 'none'; }, 4500);
}

// ═══════════════════════════════════════════════════════════
//  POLL LOOP
// ═══════════════════════════════════════════════════════════
async function poll() {
  await checkIncomingPairings();
  await checkPairingResponse();
  await pollMessages();
  updateMessageTimers();
}

// ═══════════════════════════════════════════════════════════
//  BOOT
// ═══════════════════════════════════════════════════════════
async function boot() {
  try {
    // Charger les nonces persistants AVANT toute validation
    loadPersistedNonces();
    
    // Vérifier que Web Crypto API est disponible
    if (!crypto || !crypto.subtle) {
      throw new Error('Web Crypto API non disponible. Vérifier : navigateur supporté, HTTPS ou localhost.');
    }

    const steps = ['step-1','step-2','step-3','step-4'];
    const delays = [350, 800, 1300, 1750];
    for (let i=0; i<steps.length; i++) {
      setTimeout(() => {
        const el = document.getElementById(steps[i]);
        if (el) el.className = 'load-step active';
      }, delays[i]);
      setTimeout(() => {
        const el = document.getElementById(steps[i]);
        if (el) el.className = 'load-step done';
      }, delays[i]+350);
    }

    // Générer les deux paires de clés
    S.myECDHKeyPair = await generateECDHKeyPair();
  S.mySignKeyPair = await generateSignKeyPair();
  S.myPubKeyB64 = await exportPubKey(S.myECDHKeyPair.publicKey);
  S.mySignPubKeyB64 = await exportPubKey(S.mySignKeyPair.publicKey);
  S.myFingerprint = await keyFingerprint(S.myPubKeyB64 + S.mySignPubKeyB64);

  await syncClock();

  S.myId = genId(28);
  S.idExpiresAt = now() + ID_DURATION;
  await store(`user:${S.myId}`, {
    pubKey: S.myPubKeyB64,
    signPubKey: S.mySignPubKeyB64,
    createdAt: now(),
    fp: S.myFingerprint
  });

  await new Promise(r => setTimeout(r, 2200));

  document.getElementById('loading').style.display = 'none';
  document.getElementById('captcha').style.display = 'flex';
  drawCaptcha();

  setInterval(async () => {
    const msgKeys = await listKeys('msg:');
    const t = now();
    for (const k of msgKeys) {
      const data = await load(k);
      if (data && t > data.expiresAt + 10000) await del(k);
    }
  }, 30000);
  } catch(err) {
    /* boot error during initialization */
    document.getElementById('loading').style.display = 'none';
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = 'position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); background:#ffb3b3; padding:20px; border-radius:8px; color:#1a1a1a; z-index:9999; max-width:400px; text-align:center;';
    errorDiv.innerHTML = `<strong>Erreur au démarrage :</strong><br>${err.message}<br><br>Essayez: <strong>http://localhost:3000</strong> au lieu de l'adresse IP.`;
    document.body.appendChild(errorDiv);
  }
}

window.addEventListener('load', boot);
window.addEventListener('beforeunload', () => { if (S.myId) del(`user:${S.myId}`); });
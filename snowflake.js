'use strict';

const crypto = require('crypto');
const https = require('https');
const http = require('http');
const net = require('net');

let nodeDatachannel = null;
try {
  nodeDatachannel = require('node-datachannel');
} catch (_) {
  nodeDatachannel = null;
}

class SnowflakeProxy {
  constructor(options = {}) {
    this.enabled = false;
    this.brokerUrl = options.brokerUrl || 'https://snowflake-broker.torproject.net/';
    this.relayUrl = options.relayUrl || 'wss://snowflake.torproject.net/';
    this.stunServers = options.stunServers || [
      'stun:stun.l.google.com:19302',
      'stun:stun.voip.blackberry.com:3478'
    ];
    this.turnServers = options.turnServers || [];
    this.activePeers = new Map();
    this.maxPeers = options.maxPeers || 5;
    this.stats = { totalRelayed: 0, bytesRelayed: 0, peakPeers: 0, failedConnections: 0 };
    this.trafficShaper = new TrafficShaper();
    this.pollInterval = null;
    this.pollIntervalMs = options.pollIntervalMs || 5000;
    this.natType = null;
    this.hasWebRTC = nodeDatachannel !== null;
  }

  enable() {
    this.enabled = true;
    if (this.hasWebRTC) {
      this.startPolling();
    }
    return {
      status: 'enabled',
      broker: this.brokerUrl,
      stunServers: this.stunServers,
      webrtc: this.hasWebRTC ? 'native' : 'unavailable'
    };
  }

  disable() {
    this.enabled = false;
    this.stopPolling();
    for (const [id] of this.activePeers) {
      this.disconnectPeer(id);
    }
    return { status: 'disabled', peersDisconnected: this.activePeers.size };
  }

  isEnabled() {
    return this.enabled;
  }

  startPolling() {
    if (this.pollInterval) return;
    this.pollInterval = setInterval(() => {
      if (this.activePeers.size < this.maxPeers) {
        this.requestClientFromBroker().catch(() => {});
      }
    }, this.pollIntervalMs);
  }

  stopPolling() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  requestClientFromBroker() {
    return new Promise((resolve, reject) => {
      if (!this.enabled) return reject(new Error('Proxy not enabled'));
      if (this.activePeers.size >= this.maxPeers) return reject(new Error('Max peers reached'));

      const body = JSON.stringify({
        Version: '1.3',
        Sid: crypto.randomBytes(16).toString('hex'),
        Type: 'proxy'
      });

      const url = new URL(this.brokerUrl + 'proxy');
      const transport = url.protocol === 'https:' ? https : http;
      const req = transport.request({
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body)
        },
        timeout: 10000
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.Status === 'client match' && parsed.Offer) {
              this.handleBrokerOffer(parsed.Offer, parsed.RelayURL || this.relayUrl)
                .then(resolve)
                .catch(reject);
            } else {
              resolve({ status: 'no_client', raw: parsed.Status });
            }
          } catch (e) {
            reject(new Error('Invalid broker response'));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Broker timeout')); });
      req.write(body);
      req.end();
    });
  }

  handleBrokerOffer(sdpOffer, relayUrl) {
    return new Promise((resolve, reject) => {
      if (!this.hasWebRTC) {
        return reject(new Error('node-datachannel not installed'));
      }
      const peerId = crypto.randomBytes(8).toString('hex');
      const iceServers = this.stunServers.map(s => s);
      for (const turn of this.turnServers) {
        iceServers.push(turn);
      }

      const pc = new nodeDatachannel.PeerConnection('snowflake-' + peerId, {
        iceServers: iceServers
      });

      const peerState = {
        pc: pc,
        dc: null,
        relaySocket: null,
        connectedAt: Date.now(),
        bytesRelayed: 0,
        state: 'connecting'
      };

      const connectTimeout = setTimeout(() => {
        if (peerState.state === 'connecting') {
          this.stats.failedConnections++;
          this.cleanupPeer(peerId);
          reject(new Error('Connection timeout'));
        }
      }, 30000);

      pc.onStateChange((state) => {
        if (state === 'connected') {
          peerState.state = 'connected';
          clearTimeout(connectTimeout);
        }
        if (state === 'disconnected' || state === 'failed' || state === 'closed') {
          this.cleanupPeer(peerId);
        }
      });

      pc.onGatheringStateChange((state) => {
        if (state === 'complete') {
          const answer = pc.localDescription();
          if (answer) {
            this.sendAnswerToBroker(peerId, answer.sdp).catch(() => {});
          }
        }
      });

      pc.onDataChannel((dc) => {
        peerState.dc = dc;
        this.connectToRelay(peerState, relayUrl);

        dc.onMessage((msg) => {
          const buf = Buffer.isBuffer(msg) ? msg : Buffer.from(msg);
          const shaped = this.trafficShaper.shape(buf);
          peerState.bytesRelayed += buf.length;
          this.stats.bytesRelayed += buf.length;
          this.stats.totalRelayed++;
          if (peerState.relaySocket && !peerState.relaySocket.destroyed) {
            peerState.relaySocket.write(shaped);
          }
        });

        dc.onClosed(() => {
          this.cleanupPeer(peerId);
        });
      });

      try {
        pc.setRemoteDescription(sdpOffer, 'offer');
      } catch (e) {
        clearTimeout(connectTimeout);
        this.stats.failedConnections++;
        return reject(new Error('Invalid SDP offer: ' + e.message));
      }

      this.activePeers.set(peerId, peerState);
      if (this.activePeers.size > this.stats.peakPeers) {
        this.stats.peakPeers = this.activePeers.size;
      }

      resolve({ peerId, state: 'connecting' });
    });
  }

  connectToRelay(peerState, relayUrl) {
    try {
      const url = new URL(relayUrl);
      const isSecure = url.protocol === 'wss:' || url.protocol === 'https:';
      const port = url.port || (isSecure ? 443 : 80);
      const socket = net.createConnection({ host: url.hostname, port: parseInt(port) }, () => {
        peerState.state = 'relaying';
      });
      socket.on('data', (data) => {
        const original = this.trafficShaper.unshape(data);
        if (peerState.dc) {
          try { peerState.dc.sendMessage(original); } catch (_) {}
        }
        peerState.bytesRelayed += data.length;
        this.stats.bytesRelayed += data.length;
      });
      socket.on('error', () => {});
      socket.on('close', () => {
        if (peerState.dc) {
          try { peerState.dc.close(); } catch (_) {}
        }
      });
      peerState.relaySocket = socket;
    } catch (_) {}
  }

  sendAnswerToBroker(peerId, sdpAnswer) {
    return new Promise((resolve, reject) => {
      const body = JSON.stringify({ Answer: sdpAnswer, Sid: peerId });
      const url = new URL(this.brokerUrl + 'answer');
      const transport = url.protocol === 'https:' ? https : http;
      const req = transport.request({
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body)
        },
        timeout: 10000
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve(data));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Answer timeout')); });
      req.write(body);
      req.end();
    });
  }

  connectPeer(sdpOffer) {
    if (!this.enabled) throw new Error('Snowflake proxy not enabled');
    if (this.activePeers.size >= this.maxPeers) throw new Error('Max peers reached');

    if (this.hasWebRTC) {
      return this.handleBrokerOffer(sdpOffer, this.relayUrl);
    }

    const peerId = crypto.randomBytes(8).toString('hex');
    const peerKey = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    this.activePeers.set(peerId, {
      publicKey: peerKey.publicKey,
      connectedAt: Date.now(),
      bytesRelayed: 0,
      state: 'fallback'
    });
    if (this.activePeers.size > this.stats.peakPeers) {
      this.stats.peakPeers = this.activePeers.size;
    }

    const sdpAnswer = this.buildSDP('answer');
    const ice = this.buildICECandidate();

    return Promise.resolve({ peerId, sdpAnswer, iceCandidate: ice, mode: 'fallback' });
  }

  relayData(peerId, data) {
    if (!this.enabled) throw new Error('Snowflake proxy not enabled');
    const peer = this.activePeers.get(peerId);
    if (!peer) throw new Error('Unknown peer');

    const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const shaped = this.trafficShaper.shape(input);
    const byteCount = Buffer.byteLength(shaped);

    peer.bytesRelayed += byteCount;
    this.stats.bytesRelayed += byteCount;
    this.stats.totalRelayed++;

    if (peer.dc && this.hasWebRTC) {
      try { peer.dc.sendMessage(shaped); } catch (_) {}
    }

    return {
      relayed: true,
      originalSize: input.length,
      shapedSize: byteCount,
      peerBytes: peer.bytesRelayed,
      mode: peer.state || 'fallback'
    };
  }

  disconnectPeer(peerId) {
    const peer = this.activePeers.get(peerId);
    if (!peer) return { disconnected: false };
    this.cleanupPeer(peerId);
    return { disconnected: true, bytesRelayed: peer.bytesRelayed };
  }

  cleanupPeer(peerId) {
    const peer = this.activePeers.get(peerId);
    if (!peer) return;
    if (peer.dc) { try { peer.dc.close(); } catch (_) {} }
    if (peer.pc) { try { peer.pc.close(); } catch (_) {} }
    if (peer.relaySocket) { try { peer.relaySocket.destroy(); } catch (_) {} }
    this.activePeers.delete(peerId);
  }

  buildSDP(type) {
    const sessionId = crypto.randomInt(1000000000, 9999999999);
    return [
      'v=0',
      'o=- ' + sessionId + ' 2 IN IP4 127.0.0.1',
      's=-',
      't=0 0',
      'a=group:BUNDLE 0',
      'a=msid-semantic: WMS',
      'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
      'c=IN IP4 0.0.0.0',
      'a=ice-ufrag:' + crypto.randomBytes(4).toString('hex'),
      'a=ice-pwd:' + crypto.randomBytes(12).toString('base64'),
      'a=fingerprint:sha-256 ' + this.buildDTLSFingerprint(),
      'a=setup:' + (type === 'offer' ? 'actpass' : 'active'),
      'a=mid:0',
      'a=sctp-port:5000'
    ].join('\r\n');
  }

  buildICECandidate() {
    const ip = [
      crypto.randomInt(1, 255),
      crypto.randomInt(0, 255),
      crypto.randomInt(0, 255),
      crypto.randomInt(1, 255)
    ].join('.');
    const port = crypto.randomInt(10000, 65535);
    return {
      candidate: 'candidate:' + crypto.randomBytes(4).toString('hex') + ' 1 udp ' +
        crypto.randomInt(1, 2147483647) + ' ' + ip + ' ' + port + ' typ srflx',
      sdpMid: '0',
      sdpMLineIndex: 0
    };
  }

  buildDTLSFingerprint() {
    const bytes = crypto.randomBytes(32);
    return bytes.toString('hex').toUpperCase().match(/.{2}/g).join(':');
  }

  getStats() {
    const peers = [];
    for (const [id, peer] of this.activePeers) {
      peers.push({
        peerId: id,
        state: peer.state || 'unknown',
        bytesRelayed: peer.bytesRelayed,
        connectedAt: peer.connectedAt,
        uptime: Date.now() - peer.connectedAt
      });
    }
    return {
      enabled: this.enabled,
      webrtc: this.hasWebRTC ? 'native' : 'unavailable',
      activePeers: this.activePeers.size,
      maxPeers: this.maxPeers,
      peers: peers,
      stats: this.stats
    };
  }

  destroy() {
    this.disable();
    this.stopPolling();
  }
}

class TrafficShaper {
  constructor() {
    this.patterns = [
      { name: 'video-call', chunkSizes: [1200, 1400, 800, 1000, 1300], intervalMs: 33 },
      { name: 'social-scroll', chunkSizes: [500, 1500, 2000, 300, 800], intervalMs: 100 },
      { name: 'browsing', chunkSizes: [1460, 1460, 500, 200], intervalMs: 50 }
    ];
    this.currentPattern = this.patterns[0];
    this.patternIndex = 0;
  }

  setPattern(name) {
    const pattern = this.patterns.find(p => p.name === name);
    if (!pattern) throw new Error('Unknown traffic pattern: ' + name);
    this.currentPattern = pattern;
    this.patternIndex = 0;
    return { pattern: name, intervalMs: pattern.intervalMs };
  }

  shape(data) {
    const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const targetSize = this.currentPattern.chunkSizes[this.patternIndex % this.currentPattern.chunkSizes.length];
    this.patternIndex++;
    if (input.length >= targetSize) return input;
    const padded = Buffer.alloc(targetSize);
    input.copy(padded);
    crypto.randomFillSync(padded, input.length);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(input.length, 0);
    return Buffer.concat([header, padded]);
  }

  unshape(shapedData) {
    const buf = Buffer.isBuffer(shapedData) ? shapedData : Buffer.from(shapedData);
    if (buf.length < 4) return buf;
    const originalLength = buf.readUInt32BE(0);
    if (originalLength > buf.length - 4 || originalLength <= 0) return buf;
    return buf.slice(4, 4 + originalLength);
  }

  getPatterns() {
    return this.patterns.map(p => p.name);
  }
}

class DomainFronting {
  constructor(options = {}) {
    this.frontDomains = options.frontDomains || [
      { front: 'cdn.jsdelivr.net', real: 'snowflake-broker.torproject.net' },
      { front: 'ajax.googleapis.com', real: 'snowflake-broker.torproject.net' },
      { front: 'cdnjs.cloudflare.com', real: 'snowflake-broker.torproject.net' }
    ];
    this.activeFront = null;
  }

  selectFront() {
    const idx = crypto.randomInt(0, this.frontDomains.length);
    this.activeFront = this.frontDomains[idx];
    return {
      connectTo: this.activeFront.front,
      hostHeader: this.activeFront.real
    };
  }

  buildRequest(targetPath, payload) {
    if (!this.activeFront) this.selectFront();
    const body = JSON.stringify(payload);
    return {
      hostname: this.activeFront.front,
      path: targetPath,
      method: 'POST',
      headers: {
        'Host': this.activeFront.real,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json'
      },
      body: body
    };
  }

  execute(targetPath, payload) {
    return new Promise((resolve, reject) => {
      const opts = this.buildRequest(targetPath, payload);
      const body = opts.body;
      delete opts.body;
      opts.port = 443;
      opts.timeout = 10000;
      const req = https.request(opts, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (_) { resolve({ raw: data }); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Fronting timeout')); });
      req.write(body);
      req.end();
    });
  }

  getCurrentFront() {
    return this.activeFront;
  }
}

module.exports = { SnowflakeProxy, TrafficShaper, DomainFronting };

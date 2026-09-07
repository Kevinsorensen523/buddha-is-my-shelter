'use strict';

const crypto = require('crypto');
const { secureRandomBytes } = require('./secureRandom');
const { constantTimeEqual } = require('./constantTime');

/**
 * Stateless CSRF token issuance/verification bound to a session ID and a
 * server-side secret, using HMAC-SHA256.
 */
class CsrfTokenManager {
  /**
   * @param {Buffer} secret at least 32 random bytes, kept server-side
   * @param {number} [ttlMs=3600000] token lifetime in ms; <=0 disables expiry
   */
  constructor(secret, ttlMs = 3600000) {
    this.secret = secret;
    this.ttlMs = ttlMs;
  }

  generate(sessionId) {
    const nonce = secureRandomBytes(16);
    const issuedAt = Date.now();
    const tag = this._sign(sessionId, nonce, issuedAt);
    const issuedAtBuf = Buffer.alloc(8);
    issuedAtBuf.writeBigUInt64BE(BigInt(issuedAt));
    return Buffer.concat([issuedAtBuf, nonce, tag]).toString('base64url');
  }

  verify(sessionId, token) {
    let raw;
    try {
      raw = Buffer.from(token, 'base64url');
    } catch {
      return false;
    }
    if (raw.length < 8 + 16 + 32) return false;

    const issuedAt = Number(raw.readBigUInt64BE(0));
    const nonce = raw.subarray(8, 24);
    const tag = raw.subarray(24, 56);

    if (this.ttlMs > 0 && Date.now() - issuedAt > this.ttlMs) {
      return false;
    }
    const expected = this._sign(sessionId, nonce, issuedAt);
    return constantTimeEqual(expected, tag);
  }

  _sign(sessionId, nonce, issuedAt) {
    const issuedAtBuf = Buffer.alloc(8);
    issuedAtBuf.writeBigUInt64BE(BigInt(issuedAt));
    const h = crypto.createHmac('sha256', this.secret);
    h.update(Buffer.concat([Buffer.from(sessionId, 'utf8'), nonce, issuedAtBuf]));
    return h.digest();
  }
}

module.exports = { CsrfTokenManager };

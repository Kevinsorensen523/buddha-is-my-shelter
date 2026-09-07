'use strict';

const crypto = require('crypto');

/**
 * CSPRNG-backed random generation. Never uses Math.random().
 */

/** @param {number} n @returns {Buffer} */
function secureRandomBytes(n) {
  if (!Number.isInteger(n) || n <= 0) {
    throw new RangeError('securekit: byte count must be positive');
  }
  return crypto.randomBytes(n);
}

/** @param {number} [n=32] @returns {string} URL-safe base64, unpadded */
function secureRandomToken(n = 32) {
  return secureRandomBytes(n).toString('base64url');
}

/** @param {number} [n=16] @returns {string} lowercase hex */
function secureRandomHex(n = 16) {
  return secureRandomBytes(n).toString('hex');
}

module.exports = { secureRandomBytes, secureRandomToken, secureRandomHex };

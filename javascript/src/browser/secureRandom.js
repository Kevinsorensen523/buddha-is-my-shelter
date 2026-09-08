'use strict';

/**
 * CSPRNG-backed random generation using the Web Crypto API
 * (globalThis.crypto.getRandomValues), which is available in every modern
 * browser and in Node.js 19+ without any Node-specific import -- unlike
 * ../secureRandom.js, this file never references Node's `crypto` module,
 * so bundlers (webpack, Vite, Next.js's client/Edge bundlers) never try to
 * polyfill or choke on a Node built-in.
 */

function webCrypto() {
  const c = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error(
      'securekit: Web Crypto API (globalThis.crypto.getRandomValues) is not available '
      + 'in this environment. In Node.js, use the main package export instead of `/browser`.'
    );
  }
  return c;
}

/** @param {number} n @returns {Uint8Array} */
function secureRandomBytes(n) {
  if (!Number.isInteger(n) || n <= 0) {
    throw new RangeError('securekit: byte count must be positive');
  }
  return webCrypto().getRandomValues(new Uint8Array(n));
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = typeof btoa === 'function' ? btoa(binary) : Buffer.from(binary, 'binary').toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** @param {number} [n=32] @returns {string} URL-safe base64, unpadded */
function secureRandomToken(n = 32) {
  return bytesToBase64Url(secureRandomBytes(n));
}

/** @param {number} [n=16] @returns {string} lowercase hex */
function secureRandomHex(n = 16) {
  return bytesToHex(secureRandomBytes(n));
}

module.exports = { secureRandomBytes, secureRandomToken, secureRandomHex };

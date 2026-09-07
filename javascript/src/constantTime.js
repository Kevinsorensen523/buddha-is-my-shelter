'use strict';

const crypto = require('crypto');

/**
 * Timing-attack-resistant comparison. Accepts strings or Buffers.
 * @param {string|Buffer} a
 * @param {string|Buffer} b
 * @returns {boolean}
 */
function constantTimeEqual(a, b) {
  const bufA = Buffer.isBuffer(a) ? a : Buffer.from(String(a), 'utf8');
  const bufB = Buffer.isBuffer(b) ? b : Buffer.from(String(b), 'utf8');
  if (bufA.length !== bufB.length) {
    // Length mismatch is an intentional early exit -- see Go port's
    // ConstantTimeEqual doc comment for rationale.
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = { constantTimeEqual };

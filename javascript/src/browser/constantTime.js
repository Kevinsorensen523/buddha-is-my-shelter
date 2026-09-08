'use strict';

/**
 * Timing-attack-resistant comparison, implemented in pure JS with no Node
 * dependency so it's safe in a browser bundle. Accumulates the XOR of
 * every byte pair without early-exiting on the first mismatch (the same
 * property Node's crypto.timingSafeEqual provides), only branching once at
 * the very end.
 */
function constantTimeEqual(a, b) {
  const bufA = typeof a === 'string' ? new TextEncoder().encode(a) : a;
  const bufB = typeof b === 'string' ? new TextEncoder().encode(b) : b;
  if (bufA.length !== bufB.length) {
    // Length mismatch is an intentional early exit -- see the Go port's
    // ConstantTimeEqual doc comment for rationale.
    return false;
  }
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) {
    diff |= bufA[i] ^ bufB[i];
  }
  return diff === 0;
}

module.exports = { constantTimeEqual };

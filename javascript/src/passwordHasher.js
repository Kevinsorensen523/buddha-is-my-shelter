'use strict';

/**
 * Argon2id password hashing via the `argon2` package (native bindings to
 * the reference Argon2 library). Falls back to bcrypt (via `bcryptjs`) if
 * the argon2 native binding fails to load on the current runtime/platform.
 *
 * Output when using Argon2id is the standard PHC string, cross-compatible
 * with the Go/PHP/Python/Java ports:
 *   $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
 */

let argon2 = null;
try {
  // eslint-disable-next-line global-require
  argon2 = require('argon2');
} catch {
  argon2 = null;
}
const bcrypt = require('bcryptjs');

const DEFAULTS = {
  memoryCostKiB: 64 * 1024,
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
};

class PasswordHasher {
  constructor(options = {}) {
    this.options = { ...DEFAULTS, ...options };
    this.usingArgon2 = argon2 !== null;
  }

  async hash(password) {
    if (!password) {
      throw new TypeError('securekit: password must not be empty');
    }
    if (this.usingArgon2) {
      return argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: this.options.memoryCostKiB,
        timeCost: this.options.timeCost,
        parallelism: this.options.parallelism,
        hashLength: this.options.hashLength,
      });
    }
    return bcrypt.hash(password, 12);
  }

  async verify(password, encodedHash) {
    if (encodedHash.startsWith('$argon2')) {
      if (!this.usingArgon2) return false;
      try {
        return await argon2.verify(encodedHash, password);
      } catch {
        return false;
      }
    }
    if (encodedHash.startsWith('$2')) {
      return bcrypt.compare(password, encodedHash);
    }
    return false;
  }

  async needsRehash(encodedHash) {
    if (this.usingArgon2 && encodedHash.startsWith('$argon2')) {
      return argon2.needsRehash(encodedHash, {
        type: argon2.argon2id,
        memoryCost: this.options.memoryCostKiB,
        timeCost: this.options.timeCost,
        parallelism: this.options.parallelism,
      });
    }
    if (encodedHash.startsWith('$2')) {
      // A bcrypt hash needs rehashing to Argon2id if that's now available;
      // otherwise it's already the best this runtime can do.
      return this.usingArgon2;
    }
    // Unrecognized/unparsable hash: safest to signal a rehash is needed.
    return true;
  }
}

module.exports = { PasswordHasher };

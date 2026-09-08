'use strict';

const { SymmetricEncryptor, DecryptionError } = require('./symmetricEncryptor');

/**
 * Wraps SymmetricEncryptor with key-ID-tagged ciphertexts, so keys can be
 * rotated without losing the ability to decrypt data encrypted under a
 * previous key. Wire format: 1-byte key ID followed by whatever
 * SymmetricEncryptor.encrypt() produces. Supports up to 256 concurrently-
 * known key versions.
 */
class VersionedEncryptor {
  /**
   * @param {Map<number, Buffer>|Record<number, Buffer>} keys
   * @param {number} currentKeyId
   */
  constructor(keys, currentKeyId) {
    this.keys = keys instanceof Map ? new Map(keys) : new Map(Object.entries(keys).map(([k, v]) => [Number(k), v]));
    if (!this.keys.has(currentKeyId)) {
      throw new RangeError('securekit: current key ID not found in key set');
    }
    this.inner = new SymmetricEncryptor();
    this.currentId = currentKeyId;
  }

  /** Registers a new key version without changing which key is current. */
  addKey(id, key) {
    this.keys.set(id, key);
  }

  /** Switches which registered key new encrypt() calls use. */
  setCurrentKeyId(id) {
    if (!this.keys.has(id)) {
      throw new RangeError('securekit: key ID not found in key set');
    }
    this.currentId = id;
  }

  encrypt(plaintext, aad) {
    const blob = this.inner.encrypt(this.keys.get(this.currentId), plaintext, aad);
    return Buffer.concat([Buffer.from([this.currentId]), blob]);
  }

  /**
   * Throws the generic DecryptionError on any failure, including an
   * unrecognized key ID, to avoid leaking which key IDs are valid.
   */
  decrypt(blob, aad) {
    if (!Buffer.isBuffer(blob) || blob.length < 1) {
      throw new DecryptionError();
    }
    const id = blob[0];
    if (!this.keys.has(id)) {
      throw new DecryptionError();
    }
    return this.inner.decrypt(this.keys.get(id), blob.subarray(1), aad);
  }
}

module.exports = { VersionedEncryptor };

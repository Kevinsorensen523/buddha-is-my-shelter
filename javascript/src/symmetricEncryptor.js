'use strict';

const crypto = require('crypto');
const { secureRandomBytes } = require('./secureRandom');

/**
 * AEAD encryption using AES-256-GCM via Node's built-in `crypto` module --
 * no custom crypto.
 *
 * Nonces (IVs) are generated internally and prepended to the ciphertext;
 * there is no API to supply a caller-chosen nonce, eliminating nonce-reuse
 * misuse. Decryption failures always throw a generic error.
 */

const KEY_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;

class DecryptionError extends Error {
  constructor() {
    super('securekit: decryption failed');
    this.name = 'DecryptionError';
  }
}

class SymmetricEncryptor {
  generateKey() {
    return secureRandomBytes(KEY_LEN);
  }

  /**
   * @param {Buffer} key
   * @param {Buffer} plaintext
   * @param {Buffer} [aad]
   * @returns {Buffer} iv || ciphertext || authTag
   */
  encrypt(key, plaintext, aad) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) {
      throw new TypeError('securekit: key must be 32 bytes');
    }
    const iv = secureRandomBytes(IV_LEN);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (aad) cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, ciphertext, tag]);
  }

  /**
   * @param {Buffer} key
   * @param {Buffer} blob
   * @param {Buffer} [aad]
   * @returns {Buffer}
   */
  decrypt(key, blob, aad) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_LEN
        || !Buffer.isBuffer(blob) || blob.length < IV_LEN + TAG_LEN) {
      throw new DecryptionError();
    }
    const iv = blob.subarray(0, IV_LEN);
    const tag = blob.subarray(blob.length - TAG_LEN);
    const ciphertext = blob.subarray(IV_LEN, blob.length - TAG_LEN);
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      if (aad) decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new DecryptionError();
    }
  }

  encryptToString(key, plaintext, aad) {
    return this.encrypt(key, plaintext, aad).toString('base64');
  }

  decryptFromString(key, encoded, aad) {
    let blob;
    try {
      blob = Buffer.from(encoded, 'base64');
    } catch {
      throw new DecryptionError();
    }
    return this.decrypt(key, blob, aad);
  }
}

module.exports = { SymmetricEncryptor, DecryptionError };

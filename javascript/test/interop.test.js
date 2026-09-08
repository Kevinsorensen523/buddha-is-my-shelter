/* Cross-language interop tests. Loads the shared fixtures in ../../vectors/*.json
 * (generated once from each language's own implementation) and verifies this
 * package can consume tokens/hashes/ciphertexts produced by every other port. */

const fs = require('fs');
const path = require('path');
const { CsrfTokenManager } = require('../src/csrfTokenManager');
const { PasswordHasher } = require('../src/passwordHasher');
const { SymmetricEncryptor, DecryptionError } = require('../src/symmetricEncryptor');

const VECTORS_DIR = path.join(__dirname, '..', '..', 'vectors');

function loadVectors(name) {
  return JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, name), 'utf8'));
}

test('password hashes interop', async () => {
  const vecs = loadVectors('password_hashes.json');
  const hasher = new PasswordHasher();

  for (const [lang, hash] of Object.entries(vecs.hashes)) {
    // eslint-disable-next-line no-await-in-loop
    const ok = await hasher.verify(vecs.password, hash);
    expect(ok).toBe(true);
    if (!ok) throw new Error(`${lang}: hash did not verify (PHC format not portable)`);
  }
});

test('csrf tokens interop', () => {
  const vecs = loadVectors('csrf_tokens.json');
  const secret = Buffer.from(vecs.secretBase64, 'base64');
  const mgr = new CsrfTokenManager(secret, 0); // ttl<=0: never expires, fixture-safe

  for (const [lang, token] of Object.entries(vecs.tokens)) {
    expect(mgr.verify(vecs.sessionId, token)).toBe(true);
    if (!mgr.verify(vecs.sessionId, token)) {
      throw new Error(`${lang}: token did not verify (binary format not portable)`);
    }
  }
});

test('aead interop within compatibility group', () => {
  const vecs = loadVectors('aead_ciphertexts.json');
  const key = Buffer.from(vecs.keyBase64, 'base64');
  const enc = new SymmetricEncryptor();
  const group = new Set(vecs.compatibilityGroups.aes256gcm);

  for (const [lang, ctB64] of Object.entries(vecs.ciphertexts)) {
    const ct = Buffer.from(ctB64, 'base64');
    if (group.has(lang)) {
      expect(enc.decrypt(key, ct).toString()).toBe(vecs.plaintext);
    } else {
      expect(() => enc.decrypt(key, ct)).toThrow(DecryptionError);
    }
  }
});

const { SymmetricEncryptor, DecryptionError } = require('../src/symmetricEncryptor');

test('round trip', () => {
  const enc = new SymmetricEncryptor();
  const key = enc.generateKey();
  const ciphertext = enc.encrypt(key, Buffer.from('attack at dawn'));
  expect(enc.decrypt(key, ciphertext).toString()).toBe('attack at dawn');
});

test('rejects tampered ciphertext', () => {
  const enc = new SymmetricEncryptor();
  const key = enc.generateKey();
  const ciphertext = enc.encrypt(key, Buffer.from('secret'));
  ciphertext[ciphertext.length - 1] ^= 0xff;
  expect(() => enc.decrypt(key, ciphertext)).toThrow(DecryptionError);
});

test('nonces differ', () => {
  const enc = new SymmetricEncryptor();
  const key = enc.generateKey();
  const c1 = enc.encrypt(key, Buffer.from('same message'));
  const c2 = enc.encrypt(key, Buffer.from('same message'));
  expect(c1.equals(c2)).toBe(false);
});

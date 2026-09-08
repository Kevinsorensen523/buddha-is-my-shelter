const { VersionedEncryptor } = require('../src/versionedEncryptor');
const { secureRandomBytes } = require('../src/secureRandom');
const { DecryptionError } = require('../src/symmetricEncryptor');

test('round trip', () => {
  const key1 = secureRandomBytes(32);
  const ve = new VersionedEncryptor({ 1: key1 }, 1);

  const blob = ve.encrypt(Buffer.from('secret'));
  expect(ve.decrypt(blob).toString()).toBe('secret');
});

test('survives key rotation', () => {
  const key1 = secureRandomBytes(32);
  const key2 = secureRandomBytes(32);
  const ve = new VersionedEncryptor({ 1: key1 }, 1);

  const oldBlob = ve.encrypt(Buffer.from('encrypted with v1'));

  ve.addKey(2, key2);
  ve.setCurrentKeyId(2);
  const newBlob = ve.encrypt(Buffer.from('encrypted with v2'));

  expect(ve.decrypt(oldBlob).toString()).toBe('encrypted with v1');
  expect(ve.decrypt(newBlob).toString()).toBe('encrypted with v2');
});

test('rejects unknown key id', () => {
  const key1 = secureRandomBytes(32);
  const ve = new VersionedEncryptor({ 1: key1 }, 1);
  const blob = ve.encrypt(Buffer.from('data'));
  blob[0] = 99;

  expect(() => ve.decrypt(blob)).toThrow(DecryptionError);
});

test('constructor rejects missing current key', () => {
  const key1 = secureRandomBytes(32);
  expect(() => new VersionedEncryptor({ 1: key1 }, 5)).toThrow(RangeError);
});

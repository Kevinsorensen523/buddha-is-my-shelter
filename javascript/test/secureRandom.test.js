const { secureRandomBytes, secureRandomToken, secureRandomHex } = require('../src/secureRandom');

test('bytes has requested length', () => {
  expect(secureRandomBytes(32).length).toBe(32);
});

test('bytes are unique', () => {
  expect(secureRandomBytes(32).equals(secureRandomBytes(32))).toBe(false);
});

test('rejects non-positive length', () => {
  expect(() => secureRandomBytes(0)).toThrow(RangeError);
});

test('token is url-safe', () => {
  expect(secureRandomToken(32)).toMatch(/^[A-Za-z0-9_-]+$/);
});

test('hex is lowercase hex', () => {
  const h = secureRandomHex(16);
  expect(h).toHaveLength(32);
  expect(h).toMatch(/^[0-9a-f]+$/);
});

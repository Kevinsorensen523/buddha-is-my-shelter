const { CsrfTokenManager } = require('../src/csrfTokenManager');
const { secureRandomBytes } = require('../src/secureRandom');

test('round trip', () => {
  const mgr = new CsrfTokenManager(secureRandomBytes(32), 3600000);
  const token = mgr.generate('session-123');
  expect(mgr.verify('session-123', token)).toBe(true);
});

test('rejects wrong session', () => {
  const mgr = new CsrfTokenManager(secureRandomBytes(32), 3600000);
  const token = mgr.generate('session-A');
  expect(mgr.verify('session-B', token)).toBe(false);
});

test('rejects expired token', async () => {
  const mgr = new CsrfTokenManager(secureRandomBytes(32), 5);
  const token = mgr.generate('session-123');
  await new Promise((r) => { setTimeout(r, 30); });
  expect(mgr.verify('session-123', token)).toBe(false);
});

test('rejects forged token', () => {
  const mgr = new CsrfTokenManager(secureRandomBytes(32), 3600000);
  expect(mgr.verify('session-123', 'forged.token.value')).toBe(false);
});

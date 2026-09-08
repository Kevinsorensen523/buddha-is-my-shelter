const {
  secureRandomBytes,
  secureRandomToken,
  secureRandomHex,
  constantTimeEqual,
  isValidEmail,
  escapeHtml,
} = require('../src/browser');

test('secureRandomBytes uses Web Crypto, not Node crypto', () => {
  const a = secureRandomBytes(32);
  const b = secureRandomBytes(32);
  expect(a).toBeInstanceOf(Uint8Array);
  expect(a.length).toBe(32);
  expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
});

test('secureRandomToken is url-safe', () => {
  expect(secureRandomToken(32)).toMatch(/^[A-Za-z0-9_-]+$/);
});

test('secureRandomHex is lowercase hex', () => {
  const h = secureRandomHex(16);
  expect(h).toHaveLength(32);
  expect(h).toMatch(/^[0-9a-f]+$/);
});

test('constantTimeEqual works without Node crypto.timingSafeEqual', () => {
  expect(constantTimeEqual('abc123', 'abc123')).toBe(true);
  expect(constantTimeEqual('abc123', 'abc124')).toBe(false);
  expect(constantTimeEqual('short', 'muchlongerstring')).toBe(false);
});

test('validator functions are re-exported and functional', () => {
  expect(isValidEmail('user@example.com')).toBe(true);
  expect(escapeHtml('<script>')).not.toContain('<script>');
});

test('browser module never touches Node crypto/dns/argon2/bcryptjs', () => {
  const fs = require('fs');
  const path = require('path');
  const browserDir = path.join(__dirname, '..', 'src', 'browser');
  for (const file of fs.readdirSync(browserDir)) {
    if (!file.endsWith('.js')) continue;
    const content = fs.readFileSync(path.join(browserDir, file), 'utf8');
    expect(content).not.toMatch(/require\(['"]crypto['"]\)/);
    expect(content).not.toMatch(/require\(['"]dns['"]\)/);
    expect(content).not.toMatch(/require\(['"]argon2['"]\)/);
    expect(content).not.toMatch(/require\(['"]bcryptjs['"]\)/);
  }
});

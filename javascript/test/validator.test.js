const { isValidEmail, isValidUrl, sanitizeFilename, escapeHtml } = require('../src/validator');

test('valid emails', () => {
  expect(isValidEmail('user@example.com')).toBe(true);
  expect(isValidEmail('not-an-email')).toBe(false);
  expect(isValidEmail('user@example.com\r\nBcc: x')).toBe(false);
});

test('valid urls', () => {
  expect(isValidUrl('https://example.com/path')).toBe(true);
  expect(isValidUrl('javascript:alert(1)')).toBe(false);
  expect(isValidUrl('file:///etc/passwd')).toBe(false);
});

test('sanitizeFilename rejects traversal', () => {
  expect(() => sanitizeFilename('../../etc/passwd')).toThrow(RangeError);
});

test('sanitizeFilename accepts clean name', () => {
  expect(sanitizeFilename('report-2024.pdf')).toBe('report-2024.pdf');
});

test('escapeHtml prevents xss', () => {
  const escaped = escapeHtml('<script>alert("xss")</script>');
  expect(escaped).not.toContain('<script>');
});

const { constantTimeEqual } = require('../src/constantTime');

test('equal strings match', () => {
  expect(constantTimeEqual('abc123', 'abc123')).toBe(true);
});

test('different strings do not match', () => {
  expect(constantTimeEqual('abc123', 'abc124')).toBe(false);
});

test('different length strings do not match', () => {
  expect(constantTimeEqual('short', 'muchlongerstring')).toBe(false);
});

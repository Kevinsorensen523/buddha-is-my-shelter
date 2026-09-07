const { RateLimiter, MemoryRateLimiterStore } = require('../src/rateLimiter');

test('allows under limit and blocks over', () => {
  const rl = new RateLimiter(new MemoryRateLimiterStore(), 3, 60000);
  expect(rl.allow('client-1')).toBe(true);
  expect(rl.allow('client-1')).toBe(true);
  expect(rl.allow('client-1')).toBe(true);
  expect(rl.allow('client-1')).toBe(false);
});

test('tracks keys independently', () => {
  const rl = new RateLimiter(new MemoryRateLimiterStore(), 1, 60000);
  expect(rl.allow('client-A')).toBe(true);
  expect(rl.allow('client-B')).toBe(true);
});

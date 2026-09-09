const { RateLimiter, MemoryRateLimiterStore } = require('../src/rateLimiter');

test('allows under limit and blocks over', async () => {
  const rl = new RateLimiter(new MemoryRateLimiterStore(), 3, 60000);
  expect(await rl.allow('client-1')).toBe(true);
  expect(await rl.allow('client-1')).toBe(true);
  expect(await rl.allow('client-1')).toBe(true);
  expect(await rl.allow('client-1')).toBe(false);
});

test('tracks keys independently', async () => {
  const rl = new RateLimiter(new MemoryRateLimiterStore(), 1, 60000);
  expect(await rl.allow('client-A')).toBe(true);
  expect(await rl.allow('client-B')).toBe(true);
});

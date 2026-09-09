/* Requires a real Redis instance reachable at localhost:6379. Tests are
 * skipped automatically if Redis isn't reachable, so the rest of the
 * suite still passes without Redis, but running them for real (not
 * mocked) is what actually proves this store's atomicity claims hold. */

const { RateLimiter } = require('../src/rateLimiter');
const { RedisRateLimiterStore } = require('../src/redisRateLimiterStore');

let Redis;
try {
  // eslint-disable-next-line global-require
  Redis = require('ioredis');
} catch {
  Redis = null;
}

const describeOrSkip = Redis ? describe : describe.skip;

describeOrSkip('RedisRateLimiterStore (real Redis)', () => {
  let client;

  beforeAll(async () => {
    client = new Redis({ host: 'localhost', port: 6379, lazyConnect: true, maxRetriesPerRequest: 1 });
    try {
      await client.connect();
    } catch (e) {
      client = null;
    }
  });

  afterAll(async () => {
    if (client) await client.quit();
  });

  test('allows under limit and blocks over', async () => {
    if (!client) return; // skip: no Redis reachable
    const prefix = `securekit-test:${expect.getState().currentTestName}:`;
    const store = new RedisRateLimiterStore(client, prefix);
    const rl = new RateLimiter(store, 3, 60000);
    try {
      expect(await rl.allow('client-1')).toBe(true);
      expect(await rl.allow('client-1')).toBe(true);
      expect(await rl.allow('client-1')).toBe(true);
      expect(await rl.allow('client-1')).toBe(false);
    } finally {
      await client.del(prefix + 'client-1');
    }
  });

  test('tracks keys independently', async () => {
    if (!client) return;
    const prefix = `securekit-test:${expect.getState().currentTestName}:`;
    const store = new RedisRateLimiterStore(client, prefix);
    const rl = new RateLimiter(store, 1, 60000);
    try {
      expect(await rl.allow('client-A')).toBe(true);
      expect(await rl.allow('client-B')).toBe(true);
    } finally {
      await client.del(prefix + 'client-A', prefix + 'client-B');
    }
  });

  test('expires and resets', async () => {
    if (!client) return;
    const prefix = `securekit-test:${expect.getState().currentTestName}:`;
    const store = new RedisRateLimiterStore(client, prefix);
    const rl = new RateLimiter(store, 1, 300);
    try {
      expect(await rl.allow('client-1')).toBe(true);
      expect(await rl.allow('client-1')).toBe(false);
      await new Promise((r) => { setTimeout(r, 400); });
      expect(await rl.allow('client-1')).toBe(true);
    } finally {
      await client.del(prefix + 'client-1');
    }
  });

  test('sets expiry on first increment only', async () => {
    if (!client) return;
    const prefix = `securekit-test:${expect.getState().currentTestName}:`;
    const store = new RedisRateLimiterStore(client, prefix);
    const redisKey = prefix + 'client-1';
    try {
      await store.increment('client-1', 3600000);
      const ttl1 = await client.pttl(redisKey);

      await new Promise((r) => { setTimeout(r, 50); });
      await store.increment('client-1', 3600000);
      const ttl2 = await client.pttl(redisKey);

      expect(ttl2).toBeLessThanOrEqual(ttl1);
    } finally {
      await client.del(redisKey);
    }
  });
});

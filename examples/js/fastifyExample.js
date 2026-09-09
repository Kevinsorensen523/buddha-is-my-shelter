'use strict';

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into
 * Fastify via its hook system (onRequest runs before routing, closest
 * equivalent to Express's app.use()).
 *
 * Read ../README.md first for the reverse-proxy-trust and multi-instance
 * caveats -- they apply here identically to the Express example.
 */

const fastify = require('fastify')({ trustProxy: true }); // set to your actual proxy count/CIDR, not blindly true
const {
  CsrfTokenManager,
  MemoryRateLimiterStore,
  RateLimiter,
  secureRandomBytes,
} = require('@kevinsorensen523/buddha-is-my-shelter');

const CSRF_EXEMPT_PATHS = ['/api/webhooks'];
const csrfSecret = secureRandomBytes(32); // persist this in production
const csrf = new CsrfTokenManager(csrfSecret, 3600000);
const rateLimiter = new RateLimiter(new MemoryRateLimiterStore(), 60, 60000);

fastify.addHook('onRequest', async (request, reply) => {
  if (!(await rateLimiter.allow(request.ip))) {
    reply.code(429).send({ error: 'too many requests' });
  }
});

fastify.addHook('preHandler', async (request, reply) => {
  const isExempt = CSRF_EXEMPT_PATHS.some((p) => request.url.startsWith(p));
  if (request.method === 'POST' && !isExempt) {
    const sessionId = request.session?.id ?? 'anonymous'; // wire up @fastify/session or similar
    const token = request.headers['x-csrf-token'] ?? '';
    if (!csrf.verify(sessionId, token)) {
      reply.code(403).send({ error: 'invalid CSRF token' });
    }
  }
});

fastify.get('/csrf-token', async (request) => {
  const sessionId = request.session?.id ?? 'anonymous';
  return { csrfToken: csrf.generate(sessionId) };
});

fastify.post('/submit', async () => ({ status: 'ok' }));

fastify.listen({ port: 3000 }, () => console.log('listening on :3000'));

'use strict';

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into Koa
 * via its ctx/next middleware convention.
 *
 * Read ../README.md first for the reverse-proxy-trust and multi-instance
 * caveats -- they apply here identically to the Express example.
 */

const Koa = require('koa');
const {
  CsrfTokenManager,
  MemoryRateLimiterStore,
  RateLimiter,
  secureRandomBytes,
} = require('@kevinsorensen523/buddha-is-my-shelter');

const app = new Koa();
app.proxy = true; // trust X-Forwarded-For -- set only if you actually sit behind a known reverse proxy

const CSRF_EXEMPT_PATHS = ['/api/webhooks'];
const csrfSecret = secureRandomBytes(32); // persist this in production
const csrf = new CsrfTokenManager(csrfSecret, 3600000);
const rateLimiter = new RateLimiter(new MemoryRateLimiterStore(), 60, 60000);

app.use(async (ctx, next) => {
  // ctx.ip already respects `app.proxy` above -- see Koa's docs on
  // proxy header trust before enabling it blindly.
  if (!(await rateLimiter.allow(ctx.ip))) {
    ctx.status = 429;
    ctx.body = { error: 'too many requests' };
    return;
  }
  await next();
});

app.use(async (ctx, next) => {
  const isExempt = CSRF_EXEMPT_PATHS.some((p) => ctx.path.startsWith(p));
  if (ctx.method === 'POST' && !isExempt) {
    const sessionId = ctx.session?.id ?? 'anonymous'; // wire up koa-session or similar
    const token = ctx.get('X-CSRF-Token');
    if (!csrf.verify(sessionId, token)) {
      ctx.status = 403;
      ctx.body = { error: 'invalid CSRF token' };
      return;
    }
  }
  await next();
});

app.use(async (ctx) => {
  if (ctx.path === '/csrf-token' && ctx.method === 'GET') {
    const sessionId = ctx.session?.id ?? 'anonymous';
    ctx.body = { csrfToken: csrf.generate(sessionId) };
  } else if (ctx.path === '/submit' && ctx.method === 'POST') {
    ctx.body = { status: 'ok' };
  }
});

app.listen(3000, () => console.log('listening on :3000'));

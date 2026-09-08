'use strict';

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into an
 * Express.js app.
 */

const express = require('express');
const {
  CsrfTokenManager,
  MemoryRateLimiterStore,
  RateLimiter,
  secureRandomBytes,
} = require('@kevinsorensen523/buddha-is-my-shelter');

const app = express();
app.use(express.json());

// If this app sits behind a reverse proxy/load balancer (nginx, ALB,
// Cloudflare), req.ip returns the proxy's address for every request
// unless you tell Express which proxy hops to trust -- without this,
// rate limiting below effectively applies to all clients combined, not
// per-client. Set this to your actual proxy count/CIDR, not blindly
// `true`, which trusts every hop and lets a client spoof X-Forwarded-For.
// See https://expressjs.com/en/guide/behind-proxies.html
app.set('trust proxy', 1); // example: exactly one trusted reverse proxy hop

// PM2 cluster mode / multiple container replicas each get their own
// process and therefore their own independent MemoryRateLimiterStore and
// csrfSecret below -- a client's requests landing on different instances
// would see inconsistent rate-limit counts, and (worse) a CSRF token
// issued by one instance would fail verification on another unless
// csrfSecret is shared. Fine for a single-process dev/small deployment;
// swap MemoryRateLimiterStore for a Redis-backed store and load
// csrfSecret from a shared secret manager before scaling out.
const CSRF_EXEMPT_PATHS = ['/api/webhooks']; // third-party webhooks, bearer-token APIs, etc.

const csrfSecret = secureRandomBytes(32);
const csrf = new CsrfTokenManager(csrfSecret, 3600000);
const rateLimiter = new RateLimiter(new MemoryRateLimiterStore(), 60, 60000);

app.use((req, res, next) => {
  if (!rateLimiter.allow(req.ip)) {
    return res.status(429).json({ error: 'too many requests' });
  }
  return next();
});

app.get('/csrf-token', (req, res) => {
  const sessionId = req.session?.id ?? 'anonymous'; // wire up your session middleware
  res.json({ csrfToken: csrf.generate(sessionId) });
});

app.use((req, res, next) => {
  if (req.method === 'POST' && !CSRF_EXEMPT_PATHS.some((p) => req.path.startsWith(p))) {
    const sessionId = req.session?.id ?? 'anonymous';
    const token = req.get('X-CSRF-Token') ?? '';
    if (!csrf.verify(sessionId, token)) {
      return res.status(403).json({ error: 'invalid CSRF token' });
    }
  }
  return next();
});

app.post('/submit', (req, res) => {
  return res.json({ status: 'ok' });
});

app.listen(3000, () => console.log('listening on :3000'));

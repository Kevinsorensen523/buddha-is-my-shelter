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
} = require('@kevinsorensen523/securekit');

const app = express();
app.use(express.json());

// Persist this secret (env var / secret manager) in production instead of
// regenerating it on every process start, or all outstanding tokens break
// on deploy.
const csrfSecret = secureRandomBytes(32);
const csrf = new CsrfTokenManager(csrfSecret, 3600000);

// For multi-instance deployments, implement the RateLimiterStore interface
// against Redis instead of MemoryRateLimiterStore.
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

app.post('/submit', (req, res) => {
  const sessionId = req.session?.id ?? 'anonymous';
  const token = req.get('X-CSRF-Token') ?? '';
  if (!csrf.verify(sessionId, token)) {
    return res.status(403).json({ error: 'invalid CSRF token' });
  }
  return res.json({ status: 'ok' });
});

app.listen(3000, () => console.log('listening on :3000'));

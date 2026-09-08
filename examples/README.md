# Framework Integration Examples — Read This First

**Java has its own compatibility index too**: [java/FRAMEWORKS.md](java/FRAMEWORKS.md) -- Spring Boot's example already implements the standard `jakarta.servlet.Filter` interface, so it works unmodified on any Jakarta EE server; Micronaut gets a dedicated example since it's reactive and skips the Servlet API entirely; Hibernate/MyBatis are noted as not applicable (ORM libraries, no request pipeline).

**JS/TS frontend frameworks have their own compatibility index**: [js/FRAMEWORKS.md](js/FRAMEWORKS.md) covers React, Angular, Vue, Svelte, SolidJS, Preact, Next.js, Nuxt.js, SvelteKit, Remix, and Astro -- the short version is the same client/server split documented in the JS package's README, just mapped per framework.

**PHP has its own compatibility index**: [php/FRAMEWORKS.md](php/FRAMEWORKS.md)
sorts and categorizes ~80 PHP frameworks, pointing each actively-maintained
one at the right example (dedicated Laravel/CodeIgniter/Symfony examples,
or the generic [php/Psr15MiddlewareExample.php](php/Psr15MiddlewareExample.php)
that covers most others), and explains why the rest (testing tools,
libraries, discontinued projects) don't get one.

These examples show how to wire `CsrfTokenManager` and `RateLimiter` into
a real framework's request pipeline. They're illustrative, not
copy-paste-safe as committed — every one of them has the same three
classes of deployment gotcha, because these gotchas come from how the
*framework* manages object lifecycle and network topology, not from
anything specific to this library. Read this before adapting any example.

## 1. Stateful managers must live for the whole process, not be recreated per request

`RateLimiter` (backed by `MemoryRateLimiterStore`) and `CsrfTokenManager`
only work if the *same instance* is reused across requests — their state
(counters, the signing secret) has to persist between calls.

**This was an actual bug**, not a hypothetical, in an earlier version of
[php/LaravelMiddlewareExample.php](php/LaravelMiddlewareExample.php):
Laravel resolves route middleware fresh from the container on every
request unless you explicitly bind it as a singleton. The original example
just did `new RateLimiter(...)` in the middleware's constructor — meaning
every single request got a brand-new, empty counter. The rate limiter
never blocked anything, silently. Fixed now by binding singletons in a
service provider (shown in that file's trailing doc comment).

Check this for your own framework:
- **Laravel**: bind as `$app->singleton(...)`, don't rely on auto-resolution.
- **Express/Flask**: safe by default — a plain module-level `const`/global
  is naturally a per-process singleton, since the file runs once.
- **Spring Boot**: safe by default — `@Bean`-managed classes are singleton
  scope unless you explicitly declare otherwise.
- **Go `net/http`**: safe by default — constructed once in `main()`.

## 2. Trust your reverse proxy correctly, or rate limiting keys on the wrong IP

`request.ip()` / `req.ip` / `request.remote_addr` / `request.getRemoteAddr()`
all report the *proxy's* address, not the real client's, if your app sits
behind nginx/a load balancer/Cloudflare and the framework isn't told which
hop(s) to trust. The practical effect: every client gets rate-limited as
if they were one shared client — meaning one busy user can lock everyone
else out, and no individual abusive client is actually throttled.

Every example below now has a comment at the point where the client IP is
read, pointing at that framework's specific trust-proxy configuration
(Laravel's `TrustProxies`, Express's `app.set('trust proxy', ...)`,
Flask's `ProxyFix`, Spring's `ForwardedHeaderFilter`). Set it to your
actual proxy topology — not blindly "trust everything," which lets a
client spoof `X-Forwarded-For` and bypass rate limiting entirely.

## 3. `MemoryRateLimiterStore` / an in-process secret don't survive scaling out — and for PHP, "scaling out" means day one

Every example uses the in-memory store and a randomly-generated secret for
simplicity. Both are process-local:

- Running more than one instance (containers behind a load balancer, PM2
  cluster mode, gunicorn/uWSGI with >1 worker) means each instance has its
  own independent counters and its own independent CSRF secret. A client's
  requests landing on different instances see inconsistent rate limits,
  and a CSRF token issued by one instance fails verification on another.
- **PHP-FPM is the sharpest version of this**: it runs multiple worker
  processes with separate memory *even on a single server*. There's no
  "small deployment where this is fine" for PHP the way there arguably is
  for a single Node/Flask process — swap in a Redis-backed
  `RateLimiterStoreInterface` and load the CSRF secret from shared
  config/env from the start.

See [../THREAT_MODEL.md](../THREAT_MODEL.md#ratelimiter) for the general
version of this caveat, and [../ROADMAP.md](../ROADMAP.md) for the planned
Redis-backed reference implementation.

## 4. Don't apply CSRF checking to routes that can't have a session-bound token

Third-party webhooks (Stripe, GitHub) and bearer-token-authenticated API
routes will never send your session-bound CSRF token — a blanket "check
CSRF on every POST" breaks them. Every example now exempts a configurable
list of path prefixes; adjust it to your actual routes.

## 5. Fail fast on a missing/malformed secret

Don't let a missing `SECUREKIT_CSRF_SECRET` (or equivalent) silently fall
through to `null`/`false`/an empty string — that can make every CSRF token
trivially forgeable or crash confusingly deep in a request. Validate its
presence and length at application boot, and refuse to start otherwise
(shown in the Laravel example's service-provider registration).

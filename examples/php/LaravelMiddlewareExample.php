<?php

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into a
 * Laravel-style HTTP middleware. Not a drop-in Laravel package -- adapt the
 * constructor injection to your app's service container bindings.
 *
 * IMPORTANT -- read before using: Laravel resolves route middleware fresh
 * from the container on every request unless you explicitly bind it as a
 * singleton. If you just `new` this class up (or let auto-resolution
 * happen without a singleton binding), CsrfTokenManager and RateLimiter
 * get reconstructed every request -- RateLimiter's counters reset to zero
 * every time, so it silently blocks nothing, ever. Bind it as a singleton
 * in a service provider (shown below) so state actually persists across
 * requests within one process.
 *
 * Also see PHP-FPM's specific gotcha in this repo's THREAT_MODEL.md: even
 * a single server runs multiple PHP-FPM worker processes with separate
 * memory, so MemoryRateLimiterStore effectively does not work at all in a
 * typical PHP deployment -- not just a multi-server one. Use a
 * Redis-backed RateLimiterStore in PHP from day one, not just when you
 * scale out.
 */

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use SecureKit\CsrfTokenManager;
use SecureKit\RateLimiter;
use SecureKit\RateLimiterStoreInterface;

final class SecureKitMiddleware
{
    /**
     * Routes matching these path patterns skip the CSRF check entirely --
     * e.g. third-party webhooks (Stripe, GitHub) that can never send your
     * CSRF token, and API routes authenticated by a bearer token instead
     * of a session cookie. Adjust to your app's actual routes.
     */
    private const CSRF_EXEMPT_PATTERNS = ['api/webhooks/*', 'api/*'];

    public function __construct(
        private readonly CsrfTokenManager $csrf,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    public function handle($request, Closure $next)
    {
        if (!$this->rateLimiter->allow($this->clientKey($request))) {
            abort(429, 'Too many requests');
        }

        if ($request->isMethod('post') && !$request->is(...self::CSRF_EXEMPT_PATTERNS)) {
            $sessionId = $request->session()->getId();
            $token = $request->header('X-CSRF-Token', '');
            if (!$this->csrf->verify($sessionId, $token)) {
                abort(403, 'Invalid CSRF token');
            }
        }

        return $next($request);
    }

    /**
     * $request->ip() trusts Laravel's TrustProxies config. If this app sits
     * behind a reverse proxy/load balancer and TrustProxies isn't
     * configured for it, ip() returns the proxy's address for every
     * request -- rate-limiting everyone as if they were one client. Verify
     * config/trustedproxy.php (or the framework's equivalent) is set up
     * for your actual infrastructure before relying on this in production.
     */
    private function clientKey($request): string
    {
        return $request->ip();
    }
}

/**
 * Register in a service provider (e.g. AppServiceProvider::register()) --
 * this is the part that makes the singleton lifecycle above actually true:
 *
 *   public function register(): void
 *   {
 *       $this->app->singleton(CsrfTokenManager::class, function () {
 *           $secret = base64_decode((string) env('SECUREKIT_CSRF_SECRET'), true);
 *           if ($secret === false || strlen($secret) < 32) {
 *               // Fail fast and loud at boot -- never fall back to a
 *               // default/empty secret, which would make every CSRF token
 *               // forgeable.
 *               throw new \RuntimeException(
 *                   'SECUREKIT_CSRF_SECRET must be set to a base64-encoded 32-byte secret'
 *               );
 *           }
 *           return new CsrfTokenManager($secret, 3600);
 *       });
 *
 *       $this->app->singleton(RateLimiterStoreInterface::class, function () {
 *           // Swap for a Redis-backed implementation before deploying --
 *           // see this file's class-level doc comment for why this
 *           // matters even on a single PHP-FPM server.
 *           return new \SecureKit\MemoryRateLimiterStore();
 *       });
 *
 *       $this->app->singleton(RateLimiter::class, fn ($app) =>
 *           new RateLimiter($app->make(RateLimiterStoreInterface::class), 60, 60)
 *       );
 *
 *       $this->app->singleton(SecureKitMiddleware::class);
 *   }
 */

<?php

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into a
 * Laravel-style HTTP middleware. Not a drop-in Laravel package -- adapt the
 * constructor injection to your app's service container bindings.
 */

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use SecureKit\CsrfTokenManager;
use SecureKit\MemoryRateLimiterStore;
use SecureKit\RateLimiter;

final class SecureKitMiddleware
{
    private CsrfTokenManager $csrf;
    private RateLimiter $rateLimiter;

    public function __construct()
    {
        // In a real app, load the secret from config/env (e.g. config('app.csrf_secret')),
        // generated once via SecureKit\SecureRandom::bytes(32) and stored securely.
        $secret = base64_decode(env('SECUREKIT_CSRF_SECRET'), true);
        $this->csrf = new CsrfTokenManager($secret, 3600);

        // For multi-server deployments, implement RateLimiterStoreInterface
        // against Redis instead of MemoryRateLimiterStore.
        $this->rateLimiter = new RateLimiter(new MemoryRateLimiterStore(), 60, 60);
    }

    public function handle($request, Closure $next)
    {
        if (!$this->rateLimiter->allow($request->ip())) {
            abort(429, 'Too many requests');
        }

        if ($request->isMethod('post')) {
            $sessionId = $request->session()->getId();
            $token = $request->header('X-CSRF-Token', '');
            if (!$this->csrf->verify($sessionId, $token)) {
                abort(403, 'Invalid CSRF token');
            }
        }

        return $next($request);
    }
}

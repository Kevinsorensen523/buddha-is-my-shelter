<?php

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into
 * Symfony via a kernel event subscriber -- the idiomatic Symfony approach
 * (Symfony also supports PSR-15 middleware via symfony/psr-http-message-bridge,
 * see Psr15MiddlewareExample.php in this same directory if you'd rather
 * use that instead).
 *
 * IMPORTANT: read examples/README.md first for the singleton-lifecycle,
 * reverse-proxy-trust, and PHP-FPM-multi-worker caveats. Services
 * registered in Symfony's container are singletons by default (unlike
 * Laravel's route middleware), so the lifecycle concern from the Laravel
 * example doesn't apply here as long as you use normal service
 * autowiring rather than manually `new`-ing this class per request.
 */

declare(strict_types=1);

namespace App\EventSubscriber;

use SecureKit\CsrfTokenManager;
use SecureKit\RateLimiter;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

final class SecureKitSubscriber implements EventSubscriberInterface
{
    private const CSRF_EXEMPT_PATH_PREFIXES = ['/api/webhooks/', '/api/'];

    public function __construct(
        private readonly CsrfTokenManager $csrf,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => 'onKernelRequest'];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();

        // Symfony's Request::getClientIp() already respects the
        // framework.trusted_proxies / framework.trusted_headers config in
        // config/packages/framework.yaml -- set that to your actual proxy
        // topology (do NOT set trusted_proxies to "trust everything") or
        // this falls back to the direct TCP peer, which is the proxy's
        // address behind a reverse proxy/load balancer.
        $clientIp = $request->getClientIp() ?? 'unknown';
        if (!$this->rateLimiter->allow($clientIp)) {
            $event->setResponse(new Response('Too Many Requests', 429));
            return;
        }

        $isExempt = false;
        foreach (self::CSRF_EXEMPT_PATH_PREFIXES as $prefix) {
            if (str_starts_with($request->getPathInfo(), $prefix)) {
                $isExempt = true;
                break;
            }
        }

        if ($request->isMethod('POST') && !$isExempt) {
            $sessionId = $request->hasSession() ? $request->getSession()->getId() : '';
            $token = $request->headers->get('X-CSRF-Token', '');
            if (!$this->csrf->verify($sessionId, $token)) {
                $event->setResponse(new Response('Invalid CSRF Token', 403));
            }
        }
    }
}

/**
 * Register the CsrfTokenManager and RateLimiter as services in
 * config/services.yaml -- Symfony autowires constructor dependencies, and
 * services default to singleton (shared) scope, which is what you want:
 *
 *   services:
 *       SecureKit\CsrfTokenManager:
 *           arguments:
 *               $secret: '%env(base64:SECUREKIT_CSRF_SECRET)%'
 *               $ttlSeconds: 3600
 *
 *       SecureKit\MemoryRateLimiterStore: ~
 *       # Swap the above for a Redis-backed implementation before
 *       # deploying -- see this repo's THREAT_MODEL.md.
 *
 *       SecureKit\RateLimiter:
 *           arguments:
 *               $store: '@SecureKit\MemoryRateLimiterStore'
 *               $limit: 60
 *               $windowSeconds: 60
 *
 * Symfony's env(base64:...) processor decodes SECUREKIT_CSRF_SECRET
 * automatically; Symfony throws at boot if the env var is missing, giving
 * you the fail-fast behavior the Laravel example builds by hand.
 */

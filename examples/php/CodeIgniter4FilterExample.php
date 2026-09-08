<?php

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into a
 * CodeIgniter 4 Filter (config/Filters.php registration shown below).
 * CodeIgniter 4 predates widespread PSR-15 adoption in its core filter
 * system, so it needs its own FilterInterface implementation rather than
 * the generic Psr15MiddlewareExample.php in this same directory.
 *
 * IMPORTANT: read examples/README.md first for the singleton-lifecycle,
 * reverse-proxy-trust, and PHP-FPM-multi-worker caveats.
 */

declare(strict_types=1);

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use SecureKit\CsrfTokenManager;
use SecureKit\RateLimiter;

class SecureKitFilter implements FilterInterface
{
    private const CSRF_EXEMPT_PATH_PREFIXES = ['api/webhooks/', 'api/'];

    public function before(RequestInterface $request, $arguments = null)
    {
        [$csrf, $rateLimiter] = $this->services();

        // $request->getIPAddress() trusts CodeIgniter's own proxy IP
        // handling (Config\App::$proxyIPs). Behind a reverse proxy, set
        // that config to your actual trusted proxy list, or every request
        // is keyed on the proxy's address instead of the real client's.
        if (!$rateLimiter->allow($request->getIPAddress())) {
            return service('response')->setStatusCode(429, 'Too Many Requests');
        }

        $isExempt = false;
        foreach (self::CSRF_EXEMPT_PATH_PREFIXES as $prefix) {
            if (str_starts_with(ltrim($request->getPath(), '/'), $prefix)) {
                $isExempt = true;
                break;
            }
        }

        if ($request->getMethod() === 'post' && !$isExempt) {
            $sessionId = session()->session_id;
            $token = $request->getHeaderLine('X-CSRF-Token');
            if (!$csrf->verify($sessionId, $token)) {
                return service('response')->setStatusCode(403, 'Invalid CSRF Token');
            }
        }

        return $request;
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // no post-processing needed
    }

    /**
     * Resolve these via CodeIgniter's Services (app/Config/Services.php)
     * rather than `new`-ing them here -- CodeIgniter's default Services
     * are request-scoped by default but can be marked `true` (shared) for
     * the process lifetime, which you want for these, the same reason the
     * Laravel example needs a singleton binding.
     */
    private function services(): array
    {
        return [service('secureKitCsrf'), service('secureKitRateLimiter')];
    }
}

/**
 * Register in app/Config/Filters.php:
 *
 *   public array $aliases = [
 *       'secureKit' => \App\Filters\SecureKitFilter::class,
 *   ];
 *   public array $globals = [
 *       'before' => ['secureKit'],
 *   ];
 *
 * And define the shared services in app/Config/Services.php:
 *
 *   public static function secureKitCsrf(bool $getShared = true)
 *   {
 *       if ($getShared) {
 *           return static::getSharedInstance('secureKitCsrf');
 *       }
 *       $secret = base64_decode((string) env('SECUREKIT_CSRF_SECRET'), true);
 *       if ($secret === false || strlen($secret) < 32) {
 *           throw new \RuntimeException(
 *               'SECUREKIT_CSRF_SECRET must be a base64-encoded 32-byte secret'
 *           );
 *       }
 *       return new \SecureKit\CsrfTokenManager($secret, 3600);
 *   }
 *
 *   public static function secureKitRateLimiter(bool $getShared = true)
 *   {
 *       if ($getShared) {
 *           return static::getSharedInstance('secureKitRateLimiter');
 *       }
 *       // Swap for a Redis-backed store before deploying -- see this
 *       // repo's THREAT_MODEL.md.
 *       return new \SecureKit\RateLimiter(new \SecureKit\MemoryRateLimiterStore(), 60, 60);
 *   }
 */

<?php

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into any
 * PSR-15 (psr/http-server-middleware) compatible framework.
 *
 * This ONE file covers every framework whose middleware system implements
 * or adapts to PSR-15 -- including Symfony (via symfony/psr-http-message-bridge
 * or Mezzio), Slim Framework (native), Laminas/Mezzio (native), CakePHP 4+
 * (native), Yii3 (native), and most other actively-maintained frameworks
 * built or extended after ~2018, when PSR-15 was ratified. Adapt the
 * constructor injection to your framework's DI container / service
 * registration -- the middleware logic itself needs no changes.
 *
 * IMPORTANT: read examples/README.md first for the singleton-lifecycle,
 * reverse-proxy-trust, and PHP-FPM-multi-worker caveats that apply here
 * exactly as they do to the Laravel example.
 */

declare(strict_types=1);

namespace SecureKit\Examples;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SecureKit\CsrfTokenManager;
use SecureKit\RateLimiter;

final class SecureKitPsr15Middleware implements MiddlewareInterface
{
    private const CSRF_EXEMPT_PATH_PREFIXES = ['/api/webhooks/', '/api/'];

    public function __construct(
        private readonly CsrfTokenManager $csrf,
        private readonly RateLimiter $rateLimiter,
        private readonly ResponseFactoryInterface $responseFactory,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // $request->getServerParams()['REMOTE_ADDR'] is the direct TCP
        // peer, same trust-proxy caveat as every other example in this
        // repo: behind a reverse proxy, configure your framework's
        // trusted-proxy / X-Forwarded-For handling before relying on this
        // for real per-client rate limiting.
        $clientIp = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        if (!$this->rateLimiter->allow($clientIp)) {
            return $this->responseFactory->createResponse(429, 'Too Many Requests');
        }

        $path = $request->getUri()->getPath();
        $isExempt = false;
        foreach (self::CSRF_EXEMPT_PATH_PREFIXES as $prefix) {
            if (str_starts_with($path, $prefix)) {
                $isExempt = true;
                break;
            }
        }

        if ($request->getMethod() === 'POST' && !$isExempt) {
            $sessionId = $this->sessionIdFrom($request);
            $token = $request->getHeaderLine('X-CSRF-Token');
            if (!$this->csrf->verify($sessionId, $token)) {
                return $this->responseFactory->createResponse(403, 'Invalid CSRF Token');
            }
        }

        return $handler->handle($request);
    }

    /**
     * Adapt this to however your framework exposes the session ID through
     * a PSR-7 request -- e.g. a session middleware attribute
     * ($request->getAttribute('session')->getId()), or your framework's
     * own session service resolved via its container.
     */
    private function sessionIdFrom(ServerRequestInterface $request): string
    {
        $session = $request->getAttribute('session');
        return $session !== null ? (string) $session->getId() : '';
    }
}

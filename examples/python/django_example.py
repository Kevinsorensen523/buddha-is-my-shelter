"""Example: wiring securekit's CsrfTokenManager and RateLimiter into Django
via a class-based middleware (Django's own MIDDLEWARE setting).

Read ../README.md first for the reverse-proxy-trust and multi-instance
caveats -- they apply here identically to the Flask example.

Note: Django already ships its own CSRF protection
(django.middleware.csrf.CsrfViewMiddleware) covering the same threat this
library's CsrfTokenManager addresses. This example exists for consistency
across the toolkit's languages/frameworks, or if you specifically want
this library's stateless (no server-side session store) HMAC-based token
instead of Django's default. Don't run both CSRF systems on the same
routes -- pick one.
"""

from django.conf import settings
from django.http import HttpResponseForbidden, JsonResponse

from securekit import CsrfTokenManager, MemoryRateLimiterStore, RateLimiter, secure_random_bytes

CSRF_EXEMPT_PATH_PREFIXES = ("/api/webhooks/", "/api/")

# Django middleware classes are instantiated once per process by Django's
# own startup (not per request), so this lifecycle is correct as written --
# same reasoning as the Spring Boot/Symfony examples, unlike the Laravel
# middleware bug documented in ../README.md.
_csrf_secret = getattr(settings, "SECUREKIT_CSRF_SECRET", None) or secure_random_bytes(32)
csrf = CsrfTokenManager(_csrf_secret, ttl_seconds=3600)

# gunicorn/uWSGI with more than one worker process each get their own
# independent MemoryRateLimiterStore -- swap for a Redis-backed store
# before running more than one worker, same caveat as the Flask example.
rate_limiter = RateLimiter(MemoryRateLimiterStore(), limit=60, window_seconds=60)


class SecureKitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # request.META["REMOTE_ADDR"] trusts Django's own understanding of
        # the client address. Behind a reverse proxy, use
        # django.middleware.proxy_fix or set SECURE_PROXY_SSL_HEADER /
        # your own X-Forwarded-For parsing configured for your actual
        # proxy topology, or this returns the proxy's address for every
        # request, rate-limiting everyone as if they were one client.
        client_ip = request.META.get("REMOTE_ADDR", "unknown")
        if not rate_limiter.allow(client_ip):
            return JsonResponse({"error": "too many requests"}, status=429)

        is_exempt = request.path.startswith(CSRF_EXEMPT_PATH_PREFIXES)
        if request.method == "POST" and not is_exempt:
            session_id = request.session.session_key or ""
            token = request.headers.get("X-CSRF-Token", "")
            if not csrf.verify(session_id, token):
                return HttpResponseForbidden("Invalid CSRF token")

        return self.get_response(request)


# Register in settings.py:
#
#   MIDDLEWARE = [
#       ...,
#       "myapp.middleware.SecureKitMiddleware",
#   ]
#
# And set the secret in settings.py (fail fast if missing in production --
# don't let this silently fall back to a fresh random secret on every
# process start, or every outstanding token breaks on each deploy):
#
#   import base64, os
#   SECUREKIT_CSRF_SECRET = base64.b64decode(os.environ["SECUREKIT_CSRF_SECRET"])

"""Example: wiring securekit's CsrfTokenManager and RateLimiter into
FastAPI via its HTTP middleware decorator.

Read ../README.md first for the reverse-proxy-trust and multi-instance
caveats -- they apply here identically to the Flask example.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from securekit import CsrfTokenManager, MemoryRateLimiterStore, RateLimiter, secure_random_bytes

app = FastAPI()

CSRF_EXEMPT_PATH_PREFIXES = ("/api/webhooks", "/api/")

# uvicorn/gunicorn with more than one worker process each get their own
# independent MemoryRateLimiterStore and csrf secret -- swap for a
# Redis-backed store and a shared secret from config/env before running
# more than one worker, same caveat as the Flask example.
_csrf_secret = secure_random_bytes(32)  # persist this in production
csrf = CsrfTokenManager(_csrf_secret, ttl_seconds=3600)
rate_limiter = RateLimiter(MemoryRateLimiterStore(), limit=60, window_seconds=60)


@app.middleware("http")
async def secure_kit_middleware(request: Request, call_next):
    # request.client.host trusts the direct ASGI connection's peer
    # address. Behind a reverse proxy (nginx, ALB, Cloudflare), add
    # something like uvicorn's --proxy-headers (configured with
    # --forwarded-allow-ips for your actual proxy topology) or a
    # ProxyHeadersMiddleware, or this returns the proxy's address for
    # every request.
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_ip):
        return JSONResponse({"error": "too many requests"}, status_code=429)

    is_exempt = request.url.path.startswith(CSRF_EXEMPT_PATH_PREFIXES)
    if request.method == "POST" and not is_exempt:
        session_id = request.cookies.get("session_id", "")  # wire up your session mechanism
        token = request.headers.get("X-CSRF-Token", "")
        if not csrf.verify(session_id, token):
            return JSONResponse({"error": "invalid CSRF token"}, status_code=403)

    return await call_next(request)


@app.get("/csrf-token")
async def issue_csrf_token(request: Request):
    session_id = request.cookies.get("session_id", "anonymous")
    return {"csrfToken": csrf.generate(session_id)}


@app.post("/submit")
async def submit():
    return {"status": "ok"}

"""Example: wiring securekit's CsrfTokenManager and RateLimiter into a Flask app."""

from flask import Flask, request, abort, session

from securekit import CsrfTokenManager, MemoryRateLimiterStore, RateLimiter, secure_random_bytes

app = Flask(__name__)
app.secret_key = secure_random_bytes(32)  # use a stable, persisted secret in production

_csrf_secret = secure_random_bytes(32)  # persist this in production (env var / secret manager)
csrf = CsrfTokenManager(_csrf_secret, ttl_seconds=3600)
rate_limiter = RateLimiter(MemoryRateLimiterStore(), limit=60, window_seconds=60)

# gunicorn/uWSGI with more than one worker process each get their own
# independent MemoryRateLimiterStore and _csrf_secret above -- a client's
# requests landing on different workers see inconsistent rate-limit counts,
# and a CSRF token issued by one worker fails verification on another
# unless _csrf_secret is shared. Fine for `flask run` / a single worker;
# swap MemoryRateLimiterStore for a Redis-backed store and load
# _csrf_secret from a shared secret manager before running >1 worker.
CSRF_EXEMPT_PATHS = ("/api/webhooks",)  # third-party webhooks, bearer-token APIs, etc.


@app.before_request
def enforce_rate_limit():
    # request.remote_addr trusts Werkzeug's understanding of the client
    # address. Behind a reverse proxy (nginx, ALB, Cloudflare), wrap the
    # WSGI app in werkzeug.middleware.proxy_fix.ProxyFix (configured for
    # your actual proxy hop count) or this returns the proxy's address for
    # every request, rate-limiting everyone as if they were one client.
    if not rate_limiter.allow(request.remote_addr):
        abort(429, description="Too many requests")


@app.before_request
def enforce_csrf():
    if request.method == "POST" and not request.path.startswith(CSRF_EXEMPT_PATHS):
        session_id = session.get("id", "")
        token = request.headers.get("X-CSRF-Token", "")
        if not csrf.verify(session_id, token):
            abort(403, description="Invalid CSRF token")


@app.route("/csrf-token")
def issue_csrf_token():
    session_id = session.setdefault("id", secure_random_bytes(16).hex())
    return {"csrfToken": csrf.generate(session_id)}


@app.route("/submit", methods=["POST"])
def submit():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(debug=False)

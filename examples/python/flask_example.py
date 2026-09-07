"""Example: wiring securekit's CsrfTokenManager and RateLimiter into a Flask app."""

from flask import Flask, request, abort, session

from securekit import CsrfTokenManager, MemoryRateLimiterStore, RateLimiter, secure_random_bytes

app = Flask(__name__)
app.secret_key = secure_random_bytes(32)  # use a stable, persisted secret in production

_csrf_secret = secure_random_bytes(32)  # persist this in production (env var / secret manager)
csrf = CsrfTokenManager(_csrf_secret, ttl_seconds=3600)

# For multi-instance deployments, implement RateLimiterStore against Redis
# instead of MemoryRateLimiterStore.
rate_limiter = RateLimiter(MemoryRateLimiterStore(), limit=60, window_seconds=60)


@app.before_request
def enforce_rate_limit():
    if not rate_limiter.allow(request.remote_addr):
        abort(429, description="Too many requests")


@app.before_request
def enforce_csrf():
    if request.method == "POST":
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

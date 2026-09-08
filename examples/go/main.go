// Example: wiring securekit's CsrfTokenManager and RateLimiter into a
// standard net/http server as middleware.
package main

import (
	"log"
	"net"
	"net/http"
	"time"

	securekit "github.com/kevinsorensen523/buddha-is-my-shelter/go"
)

// Routes that skip the CSRF check -- third-party webhooks, bearer-token
// APIs, etc. Adjust to your app's actual routes.
var csrfExemptPrefixes = []string{"/api/webhooks/", "/api/"}

func main() {
	secret, err := securekit.SecureRandomBytes(32)
	if err != nil {
		log.Fatal(err)
	}
	csrf := securekit.NewCsrfTokenManager(secret, time.Hour)
	limiter := securekit.NewRateLimiter(securekit.NewMemoryStore(), 60, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("form submitted"))
	})

	handler := rateLimitMiddleware(limiter, csrfMiddleware(csrf, mux))
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func rateLimitMiddleware(limiter *securekit.RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(clientKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientKey extracts just the client's IP, without the ephemeral TCP port
// r.RemoteAddr includes -- keying the rate limiter on "IP:port" would give
// almost every request its own unique key (a new connection gets a new
// port), defeating rate limiting entirely.
//
// If this server sits behind a reverse proxy/load balancer, r.RemoteAddr
// is the proxy's address, not the real client's. Read X-Forwarded-For (or
// your proxy's equivalent header) instead, but only after configuring
// which upstream hop(s) you actually trust -- blindly trusting
// X-Forwarded-For lets any client spoof their apparent IP and bypass rate
// limiting.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // fall back to the raw value rather than an empty key
	}
	return host
}

func csrfMiddleware(csrf *securekit.CsrfTokenManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && !isCsrfExempt(r.URL.Path) {
			sessionID := sessionIDFromCookie(r) // your session lookup here
			if !csrf.Verify(sessionID, r.Header.Get("X-CSRF-Token")) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isCsrfExempt(path string) bool {
	for _, prefix := range csrfExemptPrefixes {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func sessionIDFromCookie(r *http.Request) string {
	c, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	return c.Value
}

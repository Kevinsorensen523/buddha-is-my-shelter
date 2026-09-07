// Example: wiring securekit's CsrfTokenManager and RateLimiter into a
// standard net/http server as middleware.
package main

import (
	"log"
	"net/http"
	"time"

	securekit "github.com/kevinsorensen523/securekit/go"
)

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
		if !limiter.Allow(r.RemoteAddr) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func csrfMiddleware(csrf *securekit.CsrfTokenManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			sessionID := sessionIDFromCookie(r) // your session lookup here
			if !csrf.Verify(sessionID, r.Header.Get("X-CSRF-Token")) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sessionIDFromCookie(r *http.Request) string {
	c, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	return c.Value
}

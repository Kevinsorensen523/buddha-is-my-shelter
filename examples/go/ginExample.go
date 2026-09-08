// Example: wiring securekit's CsrfTokenManager and RateLimiter into
// Gin Gonic via its gin.HandlerFunc middleware signature.
//
// Read ../README.md first for the reverse-proxy-trust and multi-instance
// caveats -- they apply here identically to the plain net/http example.
package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	securekit "github.com/kevinsorensen523/buddha-is-my-shelter/go"
)

var csrfExemptPrefixes = []string{"/api/webhooks/", "/api/"}

func main() {
	secret, err := securekit.SecureRandomBytes(32)
	if err != nil {
		panic(err)
	}
	csrf := securekit.NewCsrfTokenManager(secret, time.Hour)
	limiter := securekit.NewRateLimiter(securekit.NewMemoryStore(), 60, time.Minute)

	r := gin.Default()
	// gin.Default() already trusts all proxies for X-Forwarded-For by
	// default in some Gin versions -- call r.SetTrustedProxies() explicitly
	// with your actual proxy CIDRs (or nil to trust none) before relying
	// on c.ClientIP() for rate limiting, or a client can spoof their IP.
	_ = r.SetTrustedProxies(nil) // example: trust none; set your real proxy list in production

	r.Use(rateLimitMiddleware(limiter))
	r.Use(csrfMiddleware(csrf))

	r.POST("/submit", func(c *gin.Context) {
		c.String(http.StatusOK, "form submitted")
	})

	r.Run(":8080")
}

func rateLimitMiddleware(limiter *securekit.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow(c.ClientIP()) {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
}

func csrfMiddleware(csrf *securekit.CsrfTokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodPost && !isCsrfExempt(c.Request.URL.Path) {
			sessionID, _ := c.Cookie("session_id") // your session lookup here
			if !csrf.Verify(sessionID, c.GetHeader("X-CSRF-Token")) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		c.Next()
	}
}

func isCsrfExempt(path string) bool {
	for _, prefix := range csrfExemptPrefixes {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

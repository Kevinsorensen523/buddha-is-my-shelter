// Example: wiring securekit's CsrfTokenManager and RateLimiter into Fiber.
//
// Fiber is built on fasthttp, not Go's standard net/http -- unlike Chi
// (which is directly net/http-compatible, so ../main.go's plain net/http
// example works there unmodified), Fiber needs its own example because
// its request/response types and middleware signature are entirely
// different from net/http's.
//
// Read ../README.md first for the reverse-proxy-trust and multi-instance
// caveats -- they apply here identically to the plain net/http example.
package main

import (
	"time"

	"github.com/gofiber/fiber/v2"
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

	app := fiber.New()
	// c.IP() below only reflects X-Forwarded-For if fiber.Config{ProxyHeader: ...}
	// is set for your actual proxy topology (or EnableTrustedProxyCheck +
	// TrustedProxies) -- left at Fiber's default here, which does NOT
	// trust that header.

	app.Use(rateLimitMiddleware(limiter))
	app.Use(csrfMiddleware(csrf))

	app.Post("/submit", func(c *fiber.Ctx) error {
		return c.SendString("form submitted")
	})

	app.Listen(":8080")
}

func rateLimitMiddleware(limiter *securekit.RateLimiter) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !limiter.Allow(c.IP()) {
			return c.SendStatus(fiber.StatusTooManyRequests)
		}
		return c.Next()
	}
}

func csrfMiddleware(csrf *securekit.CsrfTokenManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if c.Method() == fiber.MethodPost && !isCsrfExempt(c.Path()) {
			sessionID := c.Cookies("session_id") // your session lookup here
			if !csrf.Verify(sessionID, c.Get("X-CSRF-Token")) {
				return c.SendStatus(fiber.StatusForbidden)
			}
		}
		return c.Next()
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

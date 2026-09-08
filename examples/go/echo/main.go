// Example: wiring securekit's CsrfTokenManager and RateLimiter into Echo
// via its echo.MiddlewareFunc signature.
//
// Read ../README.md first for the reverse-proxy-trust and multi-instance
// caveats -- they apply here identically to the plain net/http example.
package main

import (
	"net/http"
	"time"

	securekit "github.com/kevinsorensen523/buddha-is-my-shelter/go"
	"github.com/labstack/echo/v4"
)

var csrfExemptPrefixes = []string{"/api/webhooks/", "/api/"}

func main() {
	secret, err := securekit.SecureRandomBytes(32)
	if err != nil {
		panic(err)
	}
	csrf := securekit.NewCsrfTokenManager(secret, time.Hour)
	limiter := securekit.NewRateLimiter(securekit.NewMemoryStore(), 60, time.Minute)

	e := echo.New()
	// e.RealIP() (used inside c.RealIP() below) only trusts
	// X-Forwarded-For/X-Real-IP when e.IPExtractor is configured for your
	// actual proxy topology -- see Echo's echo.ExtractIPFromXFFHeader docs.
	// Left at Echo's default here, which does NOT trust those headers.

	e.Use(rateLimitMiddleware(limiter))
	e.Use(csrfMiddleware(csrf))

	e.POST("/submit", func(c echo.Context) error {
		return c.String(http.StatusOK, "form submitted")
	})

	e.Logger.Fatal(e.Start(":8080"))
}

func rateLimitMiddleware(limiter *securekit.RateLimiter) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !limiter.Allow(c.RealIP()) {
				return c.NoContent(http.StatusTooManyRequests)
			}
			return next(c)
		}
	}
}

func csrfMiddleware(csrf *securekit.CsrfTokenManager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == http.MethodPost && !isCsrfExempt(c.Path()) {
				sessionCookie, _ := c.Cookie("session_id") // your session lookup here
				sessionID := ""
				if sessionCookie != nil {
					sessionID = sessionCookie.Value
				}
				if !csrf.Verify(sessionID, c.Request().Header.Get("X-CSRF-Token")) {
					return c.NoContent(http.StatusForbidden)
				}
			}
			return next(c)
		}
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

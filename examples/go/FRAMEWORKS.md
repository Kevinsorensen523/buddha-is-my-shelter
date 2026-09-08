# Go Framework Compatibility Index

| Framework | Category | Integration |
|---|---|---|
| net/http (standard library) | Minimal/standard | [main.go](main.go) (dedicated) |
| Gin Gonic | Minimal/high-performance | [ginExample.go](ginExample.go) (dedicated) |
| Echo | Minimal/high-performance | [echoExample.go](echoExample.go) (dedicated) |
| Chi | Minimal/router | [main.go](main.go) applies directly — Chi is intentionally 100% compatible with `net/http`'s `func(http.Handler) http.Handler` middleware signature, so nothing needs adapting |
| Fiber | Express.js-style | [fiberExample.go](fiberExample.go) (dedicated — Fiber runs on `fasthttp`, not `net/http`, so its request/response types and middleware signature are entirely different, unlike Chi) |
| Beego | Full-stack/batteries-included | No dedicated example — wire into `beego.InsertFilter("*", beego.BeforeRouter, ...)`, conceptually the same before-handler check as [main.go](main.go)'s middleware, different registration API |
| Goravel | Full-stack (Laravel-style) | No dedicated example — implements Go's own `http.Middleware` interface deliberately styled after Laravel middleware; conceptually closest to the reasoning already written up in [../php/LaravelMiddlewareExample.php](../php/LaravelMiddlewareExample.php) (constructed once, not per-request) |
| Go Kit | **Toolkit, not a framework** | Not directly applicable the same way — Go Kit wraps business logic in `endpoint.Middleware` (`func(Endpoint) Endpoint`), a layer below HTTP transport, not an HTTP request middleware. If you also expose a plain HTTP transport binding, [main.go](main.go)'s `net/http` middleware still applies at that layer |
| GoFR | Modern/microservices | No dedicated example — wire into GoFR's own `app.UseMiddleware(...)`; conceptually the same before-handler check as [main.go](main.go), different registration API and request/response types (`*gofr.Context`) |

Read [../README.md](../README.md) first regardless of which framework you
use — the reverse-proxy-trust and multi-instance-state caveats apply
across all of them identically. The rate-limit-key bug found in an
earlier version of [main.go](main.go) (keying on `r.RemoteAddr`, which
includes the ephemeral TCP port) is exactly the kind of mistake each
framework's own "get the client IP" helper (`c.ClientIP()` in Gin,
`c.RealIP()` in Echo, `c.IP()` in Fiber) already avoids — but every one of
them still needs its proxy-trust setting configured correctly for your
actual infrastructure, or they return the proxy's address instead.

package examples;

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into a
 * Spring Boot request filter (javax/jakarta servlet Filter). Register it as
 * a {@code @Bean} of type {@code FilterRegistrationBean} in a real app.
 */

import java.io.IOException;

import io.github.securekit.CsrfTokenManager;
import io.github.securekit.MemoryRateLimiterStore;
import io.github.securekit.RateLimiter;
import io.github.securekit.SecureRandomUtil;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public final class SecureKitFilter implements Filter {

    // Registered as a Spring @Bean, this field initializer runs once per
    // singleton bean instance (Spring's default bean scope) -- unlike the
    // Laravel middleware example in this repo, this lifecycle is correct
    // as written. In a real app, still load the secret from config/env
    // instead of regenerating it on every process start, or all
    // outstanding tokens break on deploy.
    private final CsrfTokenManager csrf = new CsrfTokenManager(SecureRandomUtil.bytes(32), 3_600_000L);

    // Multiple app instances behind a load balancer each get their own
    // independent MemoryRateLimiterStore and csrf secret above -- a
    // client's requests landing on different instances see inconsistent
    // rate-limit counts, and a CSRF token issued by one instance fails
    // verification on another unless the secret is shared. Swap for a
    // Redis-backed RateLimiterStore and a shared secret before running
    // more than one instance.
    private final RateLimiter rateLimiter = new RateLimiter(new MemoryRateLimiterStore(), 60, 60_000L);

    // Routes that skip the CSRF check -- third-party webhooks, bearer-token
    // APIs, etc. Adjust to your app's actual routes.
    private static final String[] CSRF_EXEMPT_PREFIXES = {"/api/webhooks", "/api/"};

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // getRemoteAddr() trusts the servlet container's understanding of
        // the client address. Behind a reverse proxy/load balancer, either
        // configure Spring's ForwardedHeaderFilter (or your container's
        // equivalent) for your actual proxy hop count, or this returns the
        // proxy's address for every request, rate-limiting everyone as if
        // they were one client.
        if (!rateLimiter.allow(request.getRemoteAddr())) {
            response.sendError(429, "Too many requests");
            return;
        }

        boolean exempt = false;
        for (String prefix : CSRF_EXEMPT_PREFIXES) {
            if (request.getRequestURI().startsWith(prefix)) {
                exempt = true;
                break;
            }
        }

        if ("POST".equalsIgnoreCase(request.getMethod()) && !exempt) {
            String sessionId = request.getSession().getId();
            String token = request.getHeader("X-CSRF-Token");
            if (token == null || !csrf.verify(sessionId, token)) {
                response.sendError(403, "Invalid CSRF token");
                return;
            }
        }

        chain.doFilter(req, res);
    }
}

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

    // In a real app, load this from config/env instead of regenerating it on
    // every process start, or all outstanding tokens break on deploy.
    private final CsrfTokenManager csrf = new CsrfTokenManager(SecureRandomUtil.bytes(32), 3_600_000L);

    // For multi-instance deployments, implement RateLimiterStore against
    // Redis instead of MemoryRateLimiterStore.
    private final RateLimiter rateLimiter = new RateLimiter(new MemoryRateLimiterStore(), 60, 60_000L);

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!rateLimiter.allow(request.getRemoteAddr())) {
            response.sendError(429, "Too many requests");
            return;
        }

        if ("POST".equalsIgnoreCase(request.getMethod())) {
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

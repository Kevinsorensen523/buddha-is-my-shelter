package examples;

/**
 * Example: wiring securekit's CsrfTokenManager and RateLimiter into
 * Micronaut. Micronaut is fully reactive/non-blocking and deliberately
 * does not use the Servlet API -- HttpServerFilter is its own interface,
 * unlike Spring Boot/Quarkus-with-servlet/Payara/WildFly/Tomcat, which
 * can all reuse ../java/SecureKitFilter.java directly since it implements
 * the standard jakarta.servlet.Filter interface.
 *
 * Read ../README.md first for the reverse-proxy-trust and multi-instance
 * caveats -- they apply here identically to the Servlet Filter example.
 */

import io.github.securekit.CsrfTokenManager;
import io.github.securekit.RateLimiter;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import jakarta.inject.Inject;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

@Filter("/**")
public class SecureKitFilter implements HttpServerFilter {

    private static final String[] CSRF_EXEMPT_PREFIXES = {"/api/webhooks", "/api/"};

    // Injected as Micronaut singleton beans (the default bean scope) --
    // construct CsrfTokenManager/RateLimiter in a @Factory the same way
    // the Laravel example's service provider builds its singletons, with
    // the same fail-fast secret validation.
    @Inject
    private CsrfTokenManager csrf;

    @Inject
    private RateLimiter rateLimiter;

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        // request.getRemoteAddress() trusts Micronaut's own forwarded-header
        // handling (micronaut.server.client-address-header /
        // micronaut.server.trusted-proxies config) -- set that for your
        // actual proxy topology, or this returns the proxy's address.
        String clientIp = request.getRemoteAddress().getAddress().getHostAddress();
        if (!rateLimiter.allow(clientIp)) {
            return Mono.just(HttpResponse.status(429));
        }

        boolean exempt = false;
        for (String prefix : CSRF_EXEMPT_PREFIXES) {
            if (request.getPath().startsWith(prefix)) {
                exempt = true;
                break;
            }
        }

        if (request.getMethod().name().equals("POST") && !exempt) {
            // Adapt this to however you retrieve the session ID with
            // micronaut-session (or your own session mechanism) wired up --
            // this placeholder isn't a verified Micronaut API call.
            String sessionId = request.getAttribute("sessionId", String.class).orElse("");
            String token = request.getHeaders().get("X-CSRF-Token");
            if (token == null || !csrf.verify(sessionId, token)) {
                return Mono.just(HttpResponse.status(403));
            }
        }

        return chain.proceed(request);
    }
}

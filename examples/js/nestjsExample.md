# NestJS Usage Example

NestJS wraps Express or Fastify under the hood but has its own
decorator-based abstractions (Guards, Interceptors) that are more
idiomatic here than raw middleware. Read [../README.md](../README.md)
first for the reverse-proxy-trust and multi-instance caveats -- they
apply identically to this framework's underlying HTTP adapter.

```ts
// secure-kit.guard.ts
import { CanActivate, ExecutionContext, Injectable, ForbiddenException, HttpException, HttpStatus } from '@nestjs/common';
import { CsrfTokenManager, RateLimiter } from '@kevinsorensen523/buddha-is-my-shelter';

const CSRF_EXEMPT_PATHS = ['/api/webhooks'];

@Injectable()
export class SecureKitGuard implements CanActivate {
  // Injected as singleton providers (see module registration below) --
  // Nest providers default to singleton scope, so this lifecycle is
  // correct as written, same as the Spring Boot example in this repo.
  constructor(
    private readonly csrf: CsrfTokenManager,
    private readonly rateLimiter: RateLimiter,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    // request.ip respects Express/Fastify's own trust-proxy setting --
    // configure that at the adapter level (e.g. `app.set('trust proxy', 1)`
    // for the Express adapter), not here. RateLimiter.allow() is always
    // async (so it can support a network-backed store like Redis, not
    // just the synchronous in-memory one), which is why canActivate is
    // async here too -- Nest Guards support returning Promise<boolean>.
    if (!(await this.rateLimiter.allow(request.ip))) {
      throw new HttpException('Too Many Requests', HttpStatus.TOO_MANY_REQUESTS);
    }

    const isExempt = CSRF_EXEMPT_PATHS.some((p) => request.path.startsWith(p));
    if (request.method === 'POST' && !isExempt) {
      const sessionId = request.session?.id ?? 'anonymous';
      const token = request.headers['x-csrf-token'] ?? '';
      if (!this.csrf.verify(sessionId, token)) {
        throw new ForbiddenException('Invalid CSRF token');
      }
    }

    return true;
  }
}
```

```ts
// app.module.ts
import { Module, APP_GUARD } from '@nestjs/core';
import { CsrfTokenManager, MemoryRateLimiterStore, RateLimiter, secureRandomBytes } from '@kevinsorensen523/buddha-is-my-shelter';
import { SecureKitGuard } from './secure-kit.guard';

@Module({
  providers: [
    {
      provide: CsrfTokenManager,
      useFactory: () => {
        // Load from config/env in production, fail fast if missing --
        // don't fall back to a fresh random secret at every boot in prod,
        // or every outstanding token breaks on each deploy.
        const secret = secureRandomBytes(32);
        return new CsrfTokenManager(secret, 3600000);
      },
    },
    {
      provide: RateLimiter,
      useFactory: () =>
        // Swap MemoryRateLimiterStore for a Redis-backed implementation
        // before running more than one instance -- see THREAT_MODEL.md.
        new RateLimiter(new MemoryRateLimiterStore(), 60, 60000),
    },
    { provide: APP_GUARD, useClass: SecureKitGuard },
  ],
})
export class AppModule {}
```

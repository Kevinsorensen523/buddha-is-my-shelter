# Java Framework Compatibility Index

| Framework | Category | Integration |
|---|---|---|
| Spring Boot | Web/enterprise | [SecureKitFilter.java](SecureKitFilter.java) (dedicated) |
| Jakarta EE (Servlets, JAX-RS, JPA) | Enterprise standard | [SecureKitFilter.java](SecureKitFilter.java) applies directly — it already implements the standard `jakarta.servlet.Filter` interface, not anything Spring-specific |
| Quarkus | Cloud-native/Kubernetes | If using the servlet extension: [SecureKitFilter.java](SecureKitFilter.java) directly. If using RESTEasy Reactive (the more common default): implement `jakarta.ws.rs.container.ContainerRequestFilter` instead — same logic, different interface method (`filter(ContainerRequestContext)`) |
| Micronaut | Cloud-native/microservices | [MicronautFilterExample.java](MicronautFilterExample.java) (dedicated — Micronaut is reactive and deliberately doesn't use the Servlet API) |
| Helidon MP | Cloud-native (MicroProfile) | Same as Quarkus's JAX-RS path: `ContainerRequestFilter` |
| Helidon SE | Cloud-native (functional/reactive) | Not servlet-based at all — wire into its `WebServer` routing (`.any((req, res) -> ...)`) the same way [MicronautFilterExample.java](MicronautFilterExample.java) wires into Micronaut's reactive filter chain |
| Play Framework | Web (Akka-based, Scala/Java) | Not servlet-based — implement `play.mvc.Filter`/`EssentialFilter`; conceptually the same rate-limit/CSRF logic, different (Akka Streams-based) interface not covered by a dedicated example here |
| Hibernate | **ORM library**, not a web framework | N/A — no request pipeline to hook into; used *inside* one of the frameworks above |
| MyBatis | **Persistence library**, not a web framework | N/A — same reasoning as Hibernate |

Read [../README.md](../README.md) first regardless of which framework you
use — the reverse-proxy-trust and multi-instance-state caveats apply
across all of them identically.

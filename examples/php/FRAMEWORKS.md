# PHP Framework Compatibility Index

Sorted alphabetically — use Ctrl+F / your editor's search to jump to a
name. For every framework marked **PSR-15**, use
[Psr15MiddlewareExample.php](Psr15MiddlewareExample.php) directly; it
needs no changes to work there. Frameworks with their own dedicated
example are linked in the last column.

**Not every name below gets a working example, and that's deliberate.**
Several items in the original list aren't web frameworks at all (testing
tools, libraries, database query builders) — a CSRF-middleware example
makes no sense for them, since they never handle an HTTP request/response
cycle the way this library's modules assume. Others are dead projects with
no realistic current usage; writing "integration code" for a framework
whose last release was over a decade ago, that I can't verify against a
real current API, would risk silently shipping wrong code. Where accurate,
each entry says why.

| Framework | Category | Status | Integration |
|---|---|---|---|
| Adventure PHP Framework | Web framework | Discontinued | — |
| Agile Toolkit (Atk4) | Web framework | Maintained (as "Agile UI") | Generic PSR-15 pattern likely applies; verify against current docs |
| Atoum | **Testing tool**, not a framework | Maintained | N/A — no HTTP request cycle to integrate with |
| Aura | Framework (decoupled PSR components) | Maintained | Generic PSR-15 pattern |
| Banshee PHP framework | Web framework | Discontinued | — |
| BEAR.Sunday | Web framework (DI/hypermedia) | Maintained (niche) | Generic PSR-15 pattern (has PSR-7 support) |
| Behat | **Testing tool**, not a framework | Maintained | N/A |
| Bitweaver | CMS | Largely inactive | — (also out of scope: this is a CMS, not an app framework) |
| Bullet PHP Micro-Framework | Micro framework | Low activity | Generic PSR-7 routing; verify PSR-15 middleware support in your version |
| CakePHP | Web framework | **Actively maintained** | [Psr15MiddlewareExample.php](Psr15MiddlewareExample.php) (native PSR-15 since 4.x) |
| ClanCats Framework | Web framework | Discontinued | — |
| CodeIgniter | Web framework | **Actively maintained** | [CodeIgniter4FilterExample.php](CodeIgniter4FilterExample.php) (dedicated — CI4's Filter system predates PSR-15 in its core) |
| Codeception | **Testing tool**, not a framework | Maintained | N/A |
| CrossPHP | Web framework | Very low activity / unverifiable | — |
| crVCL PHP Framework | Web framework | Unverifiable / obscure | — |
| DASH PHP Framework | Web framework | Unverifiable / obscure | — |
| DooPHP | Web framework | Discontinued (~2013) | — |
| Elefant CMS | CMS | Low activity | — (out of scope: CMS, not app framework) |
| Fat-Free Framework (F3) | Micro framework | Some activity | Has its own routing/hive concept predating PSR-15; adapt CSRF/rate-limit calls into an F3 `beforeroute` hook manually |
| Flight | Micro framework | Low-moderate activity | Has its own filter/hook system (`Flight::before()`); adapt manually, pattern is straightforward |
| Flourish | **Utility library**, not a framework | Discontinued | N/A |
| FuelPHP | Web framework | Maintenance mode | Generic PSR-15 pattern likely needs a bridge; verify |
| Horde Application Framework | Groupware framework | Legacy | — |
| Ice Framework | Web framework | Unverifiable / obscure | — |
| Innomatic | Web framework | Discontinued | — |
| Jelix | Web framework | Low activity | — |
| Joomla Framework | Framework components | Some activity | Generic PSR-15 pattern (has PSR-7 support) |
| Kohana | Web framework | **Officially discontinued (2017)** | — |
| Konstrukt | Web framework | Discontinued | — |
| KumbiaPHP web & app Framework | Web framework | Low activity | — |
| **Laravel** | Web framework | **Actively maintained** | [LaravelMiddlewareExample.php](LaravelMiddlewareExample.php) (dedicated, and fixed a real singleton-lifecycle bug found during this project — see examples/README.md) |
| li₃ (Lithium) | Web framework | Inactive | — |
| Limonade | Micro framework | Discontinued | — |
| Lumen PHP Framework | Micro framework | **Deprecated by Laravel team** (use Laravel itself) | [LaravelMiddlewareExample.php](LaravelMiddlewareExample.php) |
| Medoo | **Database query builder**, not a framework | Maintained | N/A |
| Mockery | **Testing/mocking library**, not a framework | Maintained | N/A |
| MODX Revolution | CMS | Maintained | — (out of scope: CMS) |
| Mvc5 Framework | Web framework | Unverifiable / obscure | — |
| Nette Framework | Web framework | **Actively maintained** | PSR-15 available via community bridges (e.g. contributte/psr7-http-message); otherwise adapt into Nette's own middleware/Application events |
| Opauth | **OAuth library**, not a framework | Low activity | N/A |
| Openbiz | Web framework | Discontinued | — |
| Packfire Framework | Web framework | Discontinued | — |
| Phalcon Framework | Web framework (C extension) | **Actively maintained** | Has partial PSR-7 support and its own Micro/Mvc middleware events; generic PSR-15 example may need adaptation — verify against your Phalcon version |
| phpDaemon | Async runtime | Discontinued | — |
| PHPixie | Web framework | Low activity | Generic PSR-15 pattern likely needs a bridge; verify |
| phpPeanuts | Web framework | Unverifiable / obscure | — |
| phpspec | **Testing tool**, not a framework | Maintained | N/A |
| PHPUnit | **Testing tool**, not a framework | Maintained | N/A |
| Pop PHP Framework | Web framework | Maintained (niche) | Generic PSR-15 pattern (has PSR-7 support) |
| PRADO PHP Framework | Web framework | Legacy | — |
| PSX Framework | API framework | Low activity | Generic PSR-15 pattern (native) |
| QCubed | Web framework | Low activity | — |
| Qcodo Development Framework | Web framework | Discontinued (superseded by QCubed) | — |
| QueryPHP | Web framework | Unverifiable / obscure | — |
| Recess PHP Framework | Web framework | Discontinued (~2010) | — |
| RedCat PHP Framework | Web framework | Unverifiable / obscure | — |
| Roducks PHP MVC Framework | Web framework | Unverifiable / obscure | — |
| SabreDAV | **WebDAV/CalDAV/CardDAV library**, not a general framework | Maintained | N/A — niche protocol server, not a fit for this library's HTTP-app-layer modules |
| Silex | Micro framework | **Officially deprecated** (migrate to Symfony) | [SymfonyEventSubscriberExample.php](SymfonyEventSubscriberExample.php) |
| SilverStripe | CMS / framework | **Actively maintained** | Has its own `HTTPMiddleware` interface; pattern is analogous to Psr15MiddlewareExample.php, adapt the interface method signature |
| Slim Framework | Micro framework | **Actively maintained** | [Psr15MiddlewareExample.php](Psr15MiddlewareExample.php) (native PSR-15) |
| Sloths Framework | Web framework | Unverifiable / obscure | — |
| Solar Framework | Web framework | Discontinued | — |
| StupidlySimple Framework | Web framework | Unverifiable / obscure | — |
| Studs MVC Framework | Web framework | Unverifiable / obscure | — |
| Swoole | Async coroutine runtime (C extension) | **Actively maintained** | Different execution model — a long-running Swoole server process is naturally a singleton, so the Laravel-style "recreated per request" bug can't happen here; construct `CsrfTokenManager`/`RateLimiter` once outside the request callback and reuse them across requests inside `Swoole\Http\Server::on('request', ...)` |
| TinyMVC | Web framework | Discontinued | — |
| The Pronto Project | Web framework | Unverifiable / obscure | — |
| Tonic | Micro framework (REST) | Discontinued | — |
| TYPO3 Flow | Enterprise framework | Maintained (TYPO3 ecosystem) | Generic PSR-15 pattern likely needs a bridge; verify |
| UserFrosting | Web framework/starter kit | **Actively maintained** | Built on Slim Framework — [Psr15MiddlewareExample.php](Psr15MiddlewareExample.php) applies directly |
| Willer Framework | Web framework | Unverifiable / obscure | — |
| Workerman | Async socket server framework | **Actively maintained** | Same long-running-process pattern as Swoole above — construct managers once, outside the per-connection callback |
| Yaf PHP framework | Web framework (C extension) | Largely unmaintained (removed from modern PECL builds) | — |
| Yiistrap | Bootstrap/Yii2 widget bridge, **not a framework** | Low activity | N/A |
| Yii PHP Framework | Web framework | **Actively maintained** | Yii3 is PSR-15 native ([Psr15MiddlewareExample.php](Psr15MiddlewareExample.php)); Yii2 needs a PSR-7/15 bridge package |
| Zaphpa | Micro framework | Discontinued | — |
| Zend Framework | Web framework | **Renamed/succeeded by Laminas** (Zend Framework itself is EOL) | [Psr15MiddlewareExample.php](Psr15MiddlewareExample.php) under the Laminas/Mezzio name (native PSR-15) |
| Zest Framework | Web framework | Unverifiable / obscure | — |

## Summary

- **Dedicated examples**: Laravel, CodeIgniter, Symfony (also covers Silex migrants).
- **Covered by the one generic file**: CakePHP, Slim, Laminas/Zend, Joomla Framework, Aura, BEAR.Sunday, Pop PHP, PSX, UserFrosting, Yii3, and any other framework that implements or bridges to PSR-15 — which is most frameworks still under active development.
- **Different execution model, noted separately**: Swoole, Workerman (long-running process — actually simpler to get right than PHP-FPM, see their notes above).
- **Out of scope, explained per-row**: testing tools (PHPUnit, Mockery, phpspec, Behat, Codeception, Atoum), libraries that aren't app frameworks (Medoo, Opauth, SabreDAV, Flourish, Yiistrap), CMSes (MODX, Elefant, Bitweaver — SilverStripe is the one CMS/framework hybrid still worth a real integration if you need it), and roughly 30 discontinued or unverifiable projects where I'd rather say "no example" than guess at an API I can't confirm still exists.

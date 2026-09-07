# Security Policy

## Supported Versions

securekit is currently pre-1.0 (`0.x`). Only the latest `0.x` release of
each language package receives security fixes.

| Version | Supported |
|---|---|
| 0.x (latest) | ✅ |
| < latest 0.x | ❌ |

Once a language package reaches 1.0, this table will track supported major
versions.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report suspected vulnerabilities privately using
[GitHub's private vulnerability reporting](https://github.com/kevinsorensen523/securekit/security/advisories/new)
on this repository. If that is unavailable, email the maintainer listed on
the repository's GitHub profile with:

- A description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept code is welcome)
- The affected language package(s) and version(s)
- Any suggested remediation, if you have one

## What to Expect

- **Acknowledgement**: within 3 business days.
- **Triage**: we will confirm the issue, assess severity (using CVSS as a
  guide), and identify affected versions across all five language ports
  (an issue in the shared design often affects multiple ports at once).
- **Fix & disclosure**: we aim to ship a fix within 30 days for
  critical/high severity issues. We will coordinate a disclosure timeline
  with the reporter and credit them in the release notes (unless they
  prefer to stay anonymous).

## Scope

In scope:

- The `go/`, `php/`, `python/`, `javascript/`, and `java/` packages in this
  repository.
- Misuse-resistance failures (e.g., an API that makes nonce reuse possible,
  a timing side-channel in a "constant-time" function).

Out of scope:

- Vulnerabilities in the underlying vetted libraries themselves (report
  those upstream: golang.org/x/crypto, PHP ext-sodium, argon2-cffi,
  `cryptography`, the `argon2`/`bcryptjs` npm packages, Bouncy Castle).
  We will still want to know, so we can pin a fixed version, but the fix
  belongs upstream.
- The example integrations in `examples/`, which are illustrative and not
  hardened for production use.

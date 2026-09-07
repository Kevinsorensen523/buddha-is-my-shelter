# Contributing to securekit

Thanks for your interest in contributing! securekit maintains feature
parity across five languages, so most changes touch more than one package.

## Ground Rules

1. **No custom cryptography, ever.** Every cryptographic primitive must come
   from the vetted library for that language (see root README's table). If
   you believe a new primitive is needed, open an issue to discuss the
   library choice before writing code.
2. **Feature parity.** A new module or method should be designed with all
   five language ports in mind, even if you only implement it in one PR.
   Open an issue first (or a tracking issue with sub-tasks per language) so
   the API shape is agreed before four more PRs follow the first.
3. **Go is the reference.** When behavior is ambiguous, match what the Go
   implementation does (method names translated to each language's
   convention: `camelCase`/`PascalCase` in Go, PHP, Java, JS; `snake_case`
   in Python).
4. **Generic crypto errors.** Never let a decryption/verification failure
   message leak *why* it failed.
5. **No caller-chosen nonces/IVs.** Any new AEAD-based API must generate
   nonces internally.

## Development Workflow

1. **Research first.** Check whether the standard library or an already-used
   dependency in that language covers the need before adding a new
   dependency.
2. **Write tests first.** Each module's test suite should cover: round-trip
   success, at least one failure/rejection case, and any misuse-resistance
   property being claimed (e.g., nonce uniqueness, constant-time behavior
   at the API surface).
3. **Implement.**
4. **Run the full local test + lint suite for the language(s) you touched**
   (see each language's README "Testing" section).
5. **Update docs**: the language README's usage snippet, the root feature
   matrix if you added/removed a module, and THREAT_MODEL.md if the change
   affects a module's guarantees.
6. **Update CHANGELOG.md** under "Unreleased".

## Commit Messages

```
<type>: <description>

<optional body>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`,
`security`.

## Pull Requests

- Reference the tracking issue if this is one language's port of a
  multi-language feature.
- Describe what you tested locally (paste the test summary).
- Security-sensitive changes (anything touching a crypto module) will get
  an extra review pass — expect it, and it's not personal.

## Reporting Vulnerabilities

Do not open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md).

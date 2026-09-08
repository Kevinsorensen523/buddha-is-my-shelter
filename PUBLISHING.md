# Publishing Status & Setup

Honest status as of now: **only Go's install command actually works** —
verified end-to-end (`go get` + a real program that imports and runs it).
The other four are documented as the *intended* install command, but
nothing has been published to PyPI, npm, or Packagist yet, and Maven
Central hasn't been set up at all.

| Language | Install command | Status |
|---|---|---|
| Go | `go get github.com/kevinsorensen523/buddha-is-my-shelter/go@latest` | ✅ **works right now** — no publish step needed, `go get` resolves directly from this repo |
| PHP | `composer require kevinsorensen523/buddha-is-my-shelter` | ❌ needs a one-time Packagist submission (5 minutes, see below) |
| Python | `pip install buddha-is-my-shelter` | ❌ needs a PyPI account + token, then a tagged release |
| JavaScript | `npm install @kevinsorensen523/buddha-is-my-shelter` | ❌ needs an npm account + token, then a tagged release |
| Java | Maven/Gradle dependency | ❌ needs a Sonatype Central Portal account + GPG signing setup — the heaviest of the four |

Why I can't finish this myself: every one of these requires *your* account
(email verification, 2FA, OAuth) — there's no API that lets an assistant
create it on your behalf, nor should there be. What I *can* do is
everything short of that: the build/publish automation is already wired
up in [.github/workflows/publish.yml](.github/workflows/publish.yml) and
just needs a secret token from each registry to fire.

## 1. PHP → Packagist (easiest, do this first)

No workflow, no token, no ongoing action ever again after this one step:

1. Go to https://packagist.org and click **Sign in with GitHub**.
2. Click **Submit** (top nav).
3. Paste `https://github.com/kevinsorensen523/buddha-is-my-shelter` and submit.
4. Packagist reads `php/composer.json` and registers the package. Because
   you signed in via GitHub, Packagist auto-configures a webhook on this
   repo — every future push/tag updates Packagist automatically. Nothing
   to run, no secret to store.

After this, `composer require kevinsorensen523/buddha-is-my-shelter` works.

## 2. Python → PyPI

1. Create an account at https://pypi.org/account/register/ (2FA is
   mandatory for publishing — set it up when prompted).
2. Go to **Account Settings → API tokens → Add API token**. Scope it to
   "Entire account" for this first publish (you can't scope it to a
   project that doesn't exist on PyPI yet); narrow it to the project only
   after the first successful upload.
3. Copy the token (starts with `pypi-`). **Don't paste it in chat** — store
   it directly as a GitHub Actions secret from your own terminal:
   ```bash
   gh secret set PYPI_API_TOKEN --repo kevinsorensen523/buddha-is-my-shelter
   ```
   (it'll prompt you to paste the token; that value never appears in our conversation)
4. Tag and push a release:
   ```bash
   git tag python/v0.1.0
   git push origin python/v0.1.0
   ```
   This fires the `publish-python` job in `.github/workflows/publish.yml`.

## 3. JavaScript → npm

1. Create an account at https://www.npmjs.com/signup (2FA required for publishing).
2. Go to **Access Tokens → Generate New Token → Granular Access Token**
   (or "Automation" type), scoped to publish.
3. Store it the same way, from your own terminal:
   ```bash
   gh secret set NPM_TOKEN --repo kevinsorensen523/buddha-is-my-shelter
   ```
4. Tag and push:
   ```bash
   git tag js/v0.1.0
   git push origin js/v0.1.0
   ```
   This fires the `publish-js` job.

## 4. Java → Maven Central (deferred — most involved)

This one genuinely takes longer and I'd rather flag that honestly than
rush a half-working setup:

1. Create an account at https://central.sonatype.com.
2. Verify the `io.github.kevinsorensen523` namespace — Central Portal does
   this by checking you can prove ownership of the `kevinsorensen523`
   GitHub account (usually via a verification code committed to a repo or
   OAuth sign-in; the portal walks you through it).
3. Generate a GPG key pair (`gpg --gen-key`), publish the **public** key to
   a keyserver (`gpg --keyserver keyserver.ubuntu.com --send-keys <KEYID>`),
   and keep the **private** key + passphrase somewhere safe — you'll need
   both as GitHub secrets (`GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`) plus your
   Central Portal token (`CENTRAL_USERNAME`, `CENTRAL_PASSWORD`).
4. Ping me once you've done steps 1–3 and I'll write the actual
   `publish-java` workflow job against whichever plugin Central Portal
   currently recommends (this has changed a few times as Sonatype migrated
   off the old OSSRH flow — worth checking their current docs at that
   point rather than me guessing now).

## Verifying after publishing

```bash
pip index versions buddha-is-my-shelter        # Python
npm view @kevinsorensen523/buddha-is-my-shelter # JS
composer show kevinsorensen523/buddha-is-my-shelter # PHP, once submitted
```

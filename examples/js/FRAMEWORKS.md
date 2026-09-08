# JavaScript/TypeScript Framework Compatibility Index

Two tables: **UI frameworks & meta-frameworks** (below) — where the
browser-vs-Node split matters — and **backend/API frameworks** (Express
and friends, further down) — where it doesn't, since those all run in
Node.js exclusively.

The one distinction that decides which export you use for the first table
is simple, but easy to get wrong: **does this code run in the browser, or
on a Node.js server?** It has nothing to do with which UI framework you
picked — it's about where that specific file/function executes.

| Framework | Category | Where its code runs | What to use |
|---|---|---|---|
| React | Client-side UI library | Browser only (no backend of its own) | `/browser` export only — see note below |
| Angular | Client-side UI framework | Browser only, unless paired with Angular Universal (Node SSR) | `/browser` for components; main export only inside Universal's Node server code |
| Vue.js | Client-side UI framework | Browser only (no backend of its own) | `/browser` export only |
| Svelte | Compiles to vanilla JS | Browser only (no backend of its own) | `/browser` export only |
| SolidJS | Client-side UI framework | Browser only (no backend of its own) | `/browser` export only |
| Preact | Client-side UI library | Browser only (no backend of its own) | `/browser` export only |
| Next.js | React meta-framework | Both: Node.js (API routes, Server Components, Server Actions) **and** browser (Client Components) **and** optionally Edge Runtime | See [nextjsExample.md](nextjsExample.md) — full writeup already exists |
| Nuxt.js | Vue meta-framework | Both: Nitro server (Node by default) **and** browser (client components); can target edge/worker runtimes via Nitro presets (Cloudflare, Vercel Edge, Deno) | Main export in `server/api/*` routes / server-only composables running under the Node preset; `/browser` in `<script setup>` components and anywhere a non-Node Nitro preset is used |
| SvelteKit | Svelte meta-framework | Both: `+page.server.ts`/`+server.ts` (Node by default, or an edge adapter) **and** browser (`+page.svelte`, `.client.ts`) | Main export only in server files running under `@sveltejs/adapter-node`; `/browser` everywhere else, and in server files too if using `adapter-cloudflare`/`adapter-vercel`'s edge option |
| Remix | React meta-framework | Both: loaders/actions (Node by default, or Cloudflare Workers/Deno via adapter) **and** browser | Main export only in loaders/actions on the Node adapter; `/browser` for anything rendered/run client-side or on a non-Node adapter |
| Astro | Multi-framework ("islands") meta-framework | Both: `.astro` frontmatter/API routes (Node by default, or an edge adapter) **and** browser (hydrated islands) | Main export only in server-rendered frontmatter/API routes on `@astrojs/node`; `/browser` for hydrated client islands and non-Node adapters (Cloudflare, Deno, Vercel Edge) |

## Backend / API Frameworks (Express and friends)

Good news here, unlike the frontend table above: **every Node.js backend
framework runs entirely in the Node.js runtime** (that's the whole point
of them existing), so the main export always applies -- no `/browser`
split to worry about. The only real difference between frameworks is the
shape of their middleware/hook/guard API.

| Framework | Status | Example |
|---|---|---|
| Express | Actively maintained, most widely used | [expressExample.js](expressExample.js) |
| Fastify | Actively maintained, popular high-performance alternative | [fastifyExample.js](fastifyExample.js) |
| Koa | Actively maintained (by Express's original team), minimalist | [koaExample.js](koaExample.js) |
| NestJS | Actively maintained, decorator-based (wraps Express/Fastify) | [nestjsExample.md](nestjsExample.md) — uses a Guard, not raw middleware |
| Hapi | Maintained, plugin/route-based (`server.ext('onPreHandler', ...)`) | No dedicated example — same request/reply shape as Express, adapt directly |
| AdonisJS | Actively maintained, full-stack (Laravel-inspired) | No dedicated example — its middleware signature (`ctx, next`) matches the Koa example closely |
| Feathers.js | Maintained, real-time API framework (hooks-based) | No dedicated example — wire into a `before`/`after` hook the same way as Fastify's `preHandler` |
| Restify | Low activity | No dedicated example — Express-compatible middleware signature, adapt [expressExample.js](expressExample.js) directly |
| LoopBack | Maintained (IBM/StrongLoop), API-focused | No dedicated example — use an Interceptor, conceptually identical to the NestJS Guard above |
| Sails.js | Maintenance mode | No dedicated example — use a Policy, conceptually identical to the NestJS Guard above |
| Meteor | Niche today, different paradigm (methods/publications, not HTTP middleware) | Not applicable in the same way — Meteor's DDP-based methods aren't a request/response middleware pipeline; if you also expose plain HTTP routes (e.g. via `WebApp.connectHandlers`), that's Express-compatible middleware, so [expressExample.js](expressExample.js) applies there |

## The point that matters most: a pure SPA needs a real backend

If you're building a plain single-page app with React, Vue, Svelte,
SolidJS, Preact, or Angular *without* a meta-framework (e.g. a Vite-based
SPA, Create React App) — **all of your JS ships to the browser.** There is
no server-side code at all in that setup. This isn't a limitation of this
library to route around; it's the actual reason `PasswordHasher`,
`SymmetricEncryptor`, `CsrfTokenManager`, `RateLimiter`, and
`VersionedEncryptor` exist as separate, Node-only modules in the first
place — those operations must run somewhere the browser can't read the
secret. A plain SPA needs an actual backend (a small Express/Fastify
server, one of the meta-frameworks above, or a non-JS port of this same
library) to do that work, and the SPA itself only ever uses the
`/browser` export (`isValidEmail`, `secureRandomToken` for UI-side
niceties, `escapeHtml`) plus calls that backend's API for anything
security-sensitive.

## For the meta-frameworks (Next/Nuxt/SvelteKit/Remix/Astro)

The pattern is identical across all five, because it's really the same
underlying fact restated per framework: **"Node.js runtime" and
"browser/Edge Runtime" are the only two environments that exist, and each
framework just has its own name for the file/function boundary between
them.** [nextjsExample.md](nextjsExample.md) shows the concrete code for
Next.js specifically (Server Action vs. Client Component); the same
client/server split applies verbatim to a Nuxt server route vs. a Vue
component, a SvelteKit `+page.server.ts` vs. `+page.svelte`, a Remix
`action`/`loader` vs. component code, and an Astro frontmatter block vs. a
hydrated island — swap in that framework's own server/client file
convention and the security-relevant reasoning (and the export you import
from) doesn't change.

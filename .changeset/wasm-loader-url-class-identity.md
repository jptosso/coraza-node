---
'@coraza/core': patch
---

Resolve `URL` instances by duck-typing instead of `instanceof URL` and pre-convert
URLs to filesystem path strings before crossing into `worker_threads.Worker` and
`fs.promises.readFile`. Webpack and Turbopack can embed a second copy of
`node:url` when middleware code is bundled, so the URL the loader constructs
fails Node's native `instanceof URL` check inside `fileURLToPath`. The fallback
is an explicit `decodeURIComponent(u.pathname)` that takes no class identity
into account.

Together with the previous `createRequire` fallback, the default loader now
boots cleanly under every bundler the compatibility matrix exercises:
Express 4/5, Fastify 5, NestJS 11, Next.js 15 middleware (webpack +
Turbopack), Next.js 16 proxy (webpack + Turbopack), plain ESM, and plain
CJS — single-threaded and pool modes — with **zero `wasmSource` overrides**.

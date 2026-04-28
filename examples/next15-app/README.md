# @coraza/example-next15

Demo Next.js 15 app wrapped by `@coraza/next` via `middleware.ts` on the
Node runtime. Proves the bundler-resilient WASM loader: `createWAF` is
called bare — no `wasmSource:` override — even though Next 15's
middleware bundler rewrites `import.meta.url` to a sentinel.

## Run

```sh
pnpm install
pnpm -F '@coraza/*' build       # adapters need dist/ for workspace import
PORT=3005 pnpm -F @coraza/example-next15 dev
```

`MODE=block` (default) returns 403 on detection. `MODE=detect` only logs.
`WAF=off` disables the middleware entirely.

## Endpoints

The app implements the canonical shared HTTP contract: `/healthz`, `/`,
`/search`, `POST /echo`, `POST /upload`, plus the FTW catch-all under
`/[...ftwcatchall]`. Same routes as `examples/express-app` so the
benchmarks are apples-to-apples.

## Verify the WAF protects each surface

```sh
# benign
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://localhost:3005/search?q=hello'

# query-string SQLi
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://localhost:3005/search?q=%27+OR+1%3D1--'

# JSON XSS
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST -H 'content-type: application/json' \
  --data '{"msg":"<script>alert(1)</script>"}' \
  http://localhost:3005/echo
```

## Why this example exists

Next 15's middleware bundler / Turbopack rewrite `import.meta.url` so
the older pattern `new URL('./coraza.wasm', import.meta.url)` throws
`unsupported URL protocol:` at boot. `@coraza/core` now catches that and
falls back through `createRequire(import.meta.url).resolve(
'@coraza/core/package.json')` to locate the shipped WASM. The example's
`middleware.ts` is therefore the canonical minimum: `createWAF({ rules:
recommended() })` and that's it.

`runtime: 'nodejs'` is required on Next 15 — the Edge runtime lacks
WASI and cannot host the WASM. See `middleware.ts` for the exact shape.

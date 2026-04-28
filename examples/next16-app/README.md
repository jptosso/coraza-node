# @coraza/example-next16

Demo Next.js 16 app wrapped by `@coraza/next` via `proxy.ts` (the file
Next 16 renamed `middleware.ts` to). Same shape as the Next 15 example,
different filename and a different `config` export.

## Run

```sh
pnpm install
pnpm -F '@coraza/*' build       # adapters need dist/ for workspace import
PORT=3003 pnpm -F @coraza/example-next16 dev
```

`MODE=block` (default) returns 403 on detection. `MODE=detect` only logs.
`WAF=off` disables the proxy entirely.

## Endpoints

The app implements the canonical shared HTTP contract: `/healthz`, `/`,
`/search`, `POST /echo`, `POST /upload`, plus the FTW catch-all under
`/[...ftwcatchall]`. Same routes as `examples/express-app` and
`examples/next15-app` so the matrix and benchmarks are apples-to-apples.

## Verify the WAF protects each surface

```sh
# benign
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://localhost:3003/search?q=hello'

# query-string SQLi
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://localhost:3003/search?q=%27+OR+1%3D1--'

# JSON XSS
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST -H 'content-type: application/json' \
  --data '{"msg":"<script>alert(1)</script>"}' \
  http://localhost:3003/echo
```

## Why this example exists

Next 16 rewires the middleware filename to `proxy.ts` and removes the
`runtime: 'nodejs'` opt-in — `proxy.ts` defaults to the Node.js runtime
and rejects the option outright (`The runtime config option is not
available in Proxy files`). `import.meta.url` is preserved by Next 16's
default bundler, so `@coraza/core`'s default WASM loader path works
without any fallback gymnastics.

If your project uses a `src/` layout, this file must live at
`src/proxy.ts` — Next 16 silently ignores a `proxy.ts` at the repo root
when `src/` exists.

For full Turbopack coverage in dev mode, the bundler/framework
compatibility matrix under `testing/matrix/cases/next16-proxy-turbopack/`
runs the same three assertions through Turbopack on every PR.

# Matrix — bundler/framework/runtime compatibility tests

This directory holds the compatibility matrix that protects the repo
from shipping "works here, fails in your Next 15 middleware" regressions.
The matrix is a flat list of minimal consumer apps ("cases") that each
install `@coraza/core` and one adapter, boot, and answer three HTTP
assertions identically:

1. `GET /search?q=hello` → `200`
2. `GET /search?q=<SQLi>` → `403`
3. `POST /echo` with `{ msg: "<script>alert(1)</script>" }` → `403`

All cases expose the same four routes: `/healthz`, `/`, `/search`, and
`POST /echo`. Each case boots its own WAF inline — the factory is five
lines at the top of every entry point and honours `POOL=1`, `POOL_SIZE`,
and `MODE` env vars. The only axis each case directory represents is
**adapter × framework × module format × bundler** — everything else
(Node version, pool vs single) is parameterised by the workflow and
the driver.

## When to run it

- **Before cutting a release from `main`.** The CI matrix runs on every
  PR to `main` or `develop`, but the local runner is the fast feedback
  loop when iterating.
- **After any change to `packages/core/src/wasm.ts`, `pool.ts`, or
  adapter loader paths.** Those files control where and how the WASM is
  resolved at import time — the exact surface that bundlers trip on.
- **After a Next.js major bump.** Next 14 → 15 → 16 each changed one or
  more of: middleware default runtime, filename (`middleware.ts` →
  `proxy.ts`), `src/` layout handling, `runtime` config acceptability.

## Running locally

```sh
pnpm wasm                             # build WASM (Docker)
pnpm turbo run build --filter='./packages/*'  # compile core + adapters
pnpm matrix                           # 20 legs (10 cases × {single, pool})
```

Environment overrides (see `scripts/run-local.sh` for the full list):

```sh
CASES="express5 next15-middleware" POOL_MODES="pool" pnpm matrix
```

The local runner loops cases serially and kills each case's server
between legs. On failure, the case's stdout/stderr lands in
`testing/matrix/.build/<case>-<pool>.log`.

## The contract a case implements

Every case directory must ship:

- `package.json` — `"private": true`, one pinned framework version,
  `@coraza/core`, `@coraza/coreruleset`, and the adapter as workspace
  dependencies. Name prefix: `@coraza/matrix-<case>`.
- An entry point (`src/server.ts`, `middleware.ts`, or `proxy.ts`) that
  builds a WAF via `createWAF` / `createWAFPool` keyed off `POOL`.
- A `start` script that binds the server on `${PORT}`.
- Four identical routes: `/healthz` (200 text), `/` (200 JSON),
  `/search?q=` (200 JSON echoing `q` + `len`), `POST /echo` (200 JSON
  echoing the body).

The driver (`scripts/check.mjs`) probes `/healthz` until it returns
200, then fires the three assertions. Anything other than the expected
status on any assertion fails the leg.

## Adding a new case

Three-step checklist:

1. Drop a new directory under `cases/<name>/` with `package.json`,
   an entry point (`src/server.ts`, `middleware.ts`, or `proxy.ts`),
   and any framework-specific config. Copy an existing case as a
   template — keeping the WAF factory inline means the case has no
   out-of-tree dependency.
2. Add `<name>` to the matrix in `.github/workflows/matrix.yml` and to
   `DEFAULT_CASES` in `scripts/run-local.sh`.
3. Run `pnpm install` at the repo root (the workspace glob picks the
   new directory up), then `CASES=<name> pnpm matrix` to confirm it
   passes locally.

The three assertions are the contract. If the framework or runtime
can't satisfy them, the case should fail — that's exactly the signal
we want. Don't soften the driver for a framework-specific quirk;
either fix the adapter / core, or explicitly note in the PR that the
case is expected to fail and is staged for a follow-up.

## Why cases don't reuse `examples/`

Two reasons:

- Examples live in `examples/` and are owned by the docs + demo story.
  They change for reasons (new routes, new tutorials) that have nothing
  to do with compatibility testing. Coupling the matrix to them means
  a docs change can silently mask a loader bug.
- Cases install from `workspace:*` with a tight dependency footprint.
  Examples have dev-time goodies (`@coraza/example-shared`, pino,
  supertest, etc.) that slow the matrix install by 10-20 seconds per
  leg.

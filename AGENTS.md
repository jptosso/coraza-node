# AGENTS.md — contributor & agent guide for coraza-node

This file is the single source of truth for how to work in this repo. It's
written for both humans and AI coding agents. `CLAUDE.md` and
`.github/copilot-instructions.md` intentionally just point here so there's
one canonical doc to keep current.

## What this project is

OWASP Coraza WAF packaged as a Node.js-native SDK. The Coraza engine (Go) is
compiled to WebAssembly via TinyGo and embedded inside each npm package.
Framework adapters (Express, Fastify, Next.js, NestJS) expose idiomatic
middleware on top of a small core.

Nothing in this repo is shippable without the compiled `coraza.wasm`
artifact. Build it with `pnpm wasm` (Docker) before running adapter E2Es.

## Repository map

```
wasm/                       Go sources (TinyGo target) + ABI + Dockerfile
  ABI.md                    Canonical ABI contract — read this first
  main.go                   //export entrypoints; delegates to encoding.go
  encoding.go               Pure-Go helpers (testable, zero-unsafe)
  host_wasm.go              unsafe bridge — WASI build only. Read the audit
                            block at the top before touching.
  host_native.go            Handle-table implementation used by `go test`
  *_test.go                 Go unit, integration, bench tests
  Makefile                  wasm | wasm-docker | test | cover | bench | profile

packages/
  core/                     @coraza/core — WASM loader, WAF, Transaction, ABI client
  coreruleset/              @coraza/coreruleset — SecLang profile helpers
  express/  fastify/
  next/     nestjs/         Framework adapters. Each wraps core identically.

examples/
  shared/                   Canonical HTTP contract imported by every app
  express-app/  fastify-app/
  next-app/     nestjs-app/ Runnable demos + E2E fixtures (all implement
                            the shared contract so benchmarks are apples-to-apples)

bench/                      E2E bench runners:
                              run.ts       — autocannon, fast per-route
                              k6-run.ts    — k6, realistic mixed traffic
                              k6/*.js      — k6 scripts (mixed, per-route)

.github/workflows/
  ci.yml                    Build WASM (docker) + matrix test + per-adapter E2E
  release.yml               Changesets publish
  upstream-bump.yml         Nightly poll of coraza + coraza-coreruleset releases
```

## Architectural invariants

1. **One WASM ABI**. All adapters go through `@coraza/core`. Never add a
   direct Coraza export to an adapter package. If an adapter needs something,
   teach `core` first, version-bump the ABI if required.
2. **WAF is single-threaded per instance**. The WASM module is not re-entrant.
   Spawn multiple instances in `worker_threads` for concurrency — don't share
   one across requests. `@coraza/core` ships `WAFPool` / `createWAFPool` for
   this: one WAF per worker, least-busy dispatch, async `WorkerTransaction`.
3. **Transactions are per-request**. Cheap to create (~few µs). Never reuse
   across requests. Always `processLogging` + `close` on response end.
4. **Body phase is opt-in**. Every adapter gates bodies on
   `tx.isRequestBodyAccessible()` / `tx.isResponseBodyProcessable()` so we
   don't pay the serialization cost when rules don't care.
5. **Short-circuit on engine off**. First thing every adapter does after
   `newTransaction()` is check `tx.isRuleEngineOff()`.
6. **Static/media bypass is first-class**. The `skip` option on every adapter
   defaults to bypassing images, CSS, JS, fonts, common static prefixes. See
   `packages/core/src/skip.ts`.
7. **Default mode is `detect`, not `block`**. Safer first-run experience.
   Users flip to `block` once they've reviewed false positives.
8. **`inspectResponse` is off by default**. Doubles per-request work; only
   enable when you have response-side rules.

## The ABI

Read `wasm/ABI.md` — it's the contract. Summary of what you *must* remember:

- i32 is the ABI unit. Return codes: `0` = ok / pass, `1` = interrupted,
  `-1` = error (see `last_error()`).
- Pointer+length returns are packed into a single `i64` (`ptr << 32 | len`).
- Header sets use a compact binary packet format — zero JSON on the hot path.
- The scratch buffer is a fixed 64 KiB region whose pointer the host caches
  once (`scratch_ptr()`). Contents are invalidated at the next export call.
- Bump `abi_version`'s major when breaking. The TS side refuses to run a
  module with a mismatched major.

## Build & test

### WASM

```sh
pnpm wasm            # Docker (reproducible, used by CI)
pnpm wasm:host       # local TinyGo (fast iteration, requires tinygo 0.34+)
```

### TypeScript

```sh
pnpm install
pnpm build           # turborepo — builds core first, then adapters
pnpm test            # vitest unit tests
pnpm test:coverage   # enforces thresholds (98% lines/funcs/stmts)
pnpm e2e             # Playwright per adapter (requires built WASM)
pnpm bench           # autocannon — per-route WAF on/off comparison
pnpm k6              # k6 — realistic mixed traffic (requires k6 on PATH)
```

### Go

```sh
cd wasm
make test            # go test with race detector
make cover           # HTML coverage at build/coverage.html
make bench           # microbenchmarks
make profile         # writes cpu.prof, mem.prof, block.prof, mutex.prof
```

## Coverage expectations

- **TS packages**: 100% lines/functions/statements, ≥85% branches
  (≥95% for non-adapter packages). Thresholds enforced by `vitest.config.ts`
  in each package. Adapters are looser on branches because framework
  integrations have many defensive guards.
- **Go (wasm/)**: >85% statement coverage. Pure helpers in `encoding.go` are
  100%; the `//export` ABI shims are covered by `integration_test.go`
  running through `host_native.go`'s handle-table.
- **Mocks live in `test/mockAbi.ts`** (under `@coraza/core`). Every adapter
  test uses the same mock WAF to avoid booting the real WASM.

## Testing layers, in order of strength

1. **Pure unit (vitest)** — mock ABI, covers every TS file.
2. **Go unit (go test)** — covers the Go ABI layer end-to-end against real
   Coraza (native, not WASM).
3. **Framework integration (vitest + framework.inject / supertest)** —
   mock ABI, real framework, real HTTP semantics.
4. **E2E (Playwright)** — real WASM, real framework, real HTTP. Requires the
   built `coraza.wasm`.
5. **Benchmarks (autocannon for Node, `go test -bench` for Go)** — produce
   actual performance numbers.

If you change the ABI: all five layers need touching. Start at the WASM, then
`mockAbi.ts`, then TS types, then the Go integration test, then adapters.

## `unsafe` policy

The only file in the entire repo that uses `unsafe.Pointer` / `unsafe.Slice`
is `wasm/host_wasm.go`. It has a full audit at the top of the file
enumerating every usage and invariant. Every `readBytes`, `writeScratch`,
`hostMalloc`, and `hostPtr` has:

- a documented precondition,
- a documented postcondition / lifetime,
- a defensive bounds check (256 MiB read ceiling, 64 MiB alloc ceiling).

If you add a new use of `unsafe`: update the audit block, add the bounds
check, add a Go test.

## Coding style

- **No comments unless they explain WHY**. Identifiers carry the WHAT.
- **No runtime type validation at internal boundaries**. Trust TS types; only
  validate at system edges (user input, WASM ABI).
- **No back-compat shims or feature flags**. Change the code directly — we're
  pre-1.0.
- **Prefer editing existing files** over adding new ones. Don't split a small
  helper into its own file.
- **Never mock the database in tests**. (Not applicable here, but a shared
  monorepo norm.)
- **No emojis in code or markdown** unless the user asks.

## Release flow

- Every change that affects published packages gets a changeset
  (`pnpm changeset`).
- `main` is auto-published by the release workflow.
- `@coraza/core` and `@coraza/coreruleset` version independently.
- The nightly `upstream-bump.yml` workflow detects new Coraza / CRS releases
  and opens a PR with the rebuilt WASM + changesets.

## Known issues

1. **Local WASM build with `no_fs_access`**: the TinyGo build tag may not
   propagate consistently across toolchain versions. Use `pnpm wasm` (Docker)
   for reproducible builds. If `pnpm wasm:host` produces a binary that errors
   with `filesystem access check: ...` at `waf_create`, that's the symptom.
2. **Node E2E requires a built WASM**. Playwright's webServer will fail to
   boot if `packages/core/src/wasm/coraza.wasm` is missing or stale.

## What to change, and where

| If you're changing… | Touch |
|---|---|
| Coraza engine behavior | `wasm/main.go` + `wasm/ABI.md` + TS ABI types |
| A new WAF config option | `packages/core/src/types.ts` + `src/waf.ts` + adapters |
| Framework adapter behavior | `packages/<adapter>/src/index.ts` + its tests |
| Static-file bypass logic | `packages/core/src/skip.ts` (NOT per-adapter) |
| CRS profile preset | `packages/coreruleset/src/index.ts` |
| CI / release workflow | `.github/workflows/*.yml` |
| Docs an agent will read | THIS FILE. Not a new doc. |

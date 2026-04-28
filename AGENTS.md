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
  next15-app/   next16-app/ Runnable demos + E2E fixtures (all implement
  nestjs-app/               the shared contract so benchmarks are
                            apples-to-apples). next15-app uses
                            middleware.ts + runtime:'nodejs'; next16-app
                            uses proxy.ts.

bench/                      E2E bench runners:
                              run.ts       — autocannon, fast per-route
                              k6-run.ts    — k6, realistic mixed traffic
                              k6/*.js      — k6 scripts (mixed, per-route)

.github/workflows/
  ci.yml                    Build WASM (docker) + matrix test + per-adapter E2E
  release.yml               Changesets publish
  upstream-bump.yml         Nightly poll of coraza + coraza-coreruleset releases
```

## Priority order

**Security > Performance.** Always. This is a WAF — if it doesn't correctly
block attacks, throughput is irrelevant. Rules that follow from this
priority:

- **Never sacrifice security for performance unless the trade-off is
  explicit, controlled, and opt-in.** An env var the user consciously
  flips is acceptable; a silent fast-path that drops detections is not.
- **Fail closed on WAF errors.** If the WAF throws, crashes, or
  otherwise can't evaluate a request, the default MUST be to block
  (`onWAFError: 'block'` in adapters). Fail-open is an opt-in for
  availability-critical deployments and must be explicit.
- **Any perf change must measure block rate, not just RPS.** The
  `bench/k6` scenario counts `blocked` separately from throughput.
  A throughput gain that drops the block rate is a bug, not an
  optimization.
- **Default to stricter.** Host-regex routes to V8 (faster but backtracking-capable).
  Keep it default-on, but every bypass-shaped defensive check (like
  method/URL/addr length clipping in `encodeRequestBundle`) must keep
  the request flowing into the WAF even when data is oversized. Never
  throw into a path the adapter might catch-and-next.

See `docs/threat-model.md` for the threat model, known caveats (ReDoS,
Unicode case-insensitive, UTF-8 encoding), and the fail-closed checklist.

## Mandatory security checks & risk analysis (every change)

**Every commit** — perf tuning, refactor, new feature, doc, build change,
bump, anything — **must include an explicit security-impact check**. No
exceptions, even for "obviously harmless" edits. Bypass bugs hide in
one-line changes.

Before pushing / merging, answer these five questions in the commit
message (or PR description). If the answer to any is "I don't know,"
stop and investigate until you do.

1. **What's the security impact?** State it plainly: "no impact", "may
   bypass detection under condition X", "narrows an existing exposure",
   "adds a new code path attackers can reach", etc. If you can't
   articulate it, you haven't thought it through yet.

2. **Does any new code path handle a `throw` / reject that an attacker
   could force?** Follow every exception upward to its `catch`. If the
   catch re-throws, logs, or calls `next()`, is the request still
   evaluated or does it reach the handler unfiltered? Throwing into a
   path that falls through to `next()` is a bypass — clip, fallback,
   or fail-closed instead.

3. **Does it change what Coraza sees?** Encoding changes, truncation,
   filtering, normalization, caching — any of these can make Coraza
   evaluate a different input than what the attacker actually sent.
   Confirm behavioral equivalence or document the gap in
   `docs/threat-model.md`.

4. **Does it change when rules fire?** Skipping a phase, reordering
   calls, batching, short-circuiting on a predicate — these can cause
   anomaly-score rules (like CRS `949110`) to never reach their
   evaluation point. Phase 2 must always run, even on body-less verbs,
   for the anomaly block to fire.

5. **Are the defaults secure?** New option? Default must be the strict
   choice. New fast-path? Default off, opt-in via env var or config.
   New output format? Default must produce complete data, optimizations
   behind a flag.

**How to verify**:

- Run `pnpm -F @coraza/bench k6 -- --adapters=express` and check
  that `missed_attacks` is 0 and `blocked_attacks` matches the total
  attack count in the run. Any gap means the change opened a bypass.
- Run `pnpm -r test` — tests enforce coverage thresholds (≥98%
  lines/funcs/stmts on core; ≥85% branches on adapters). Write a test
  for any new code path, especially the error / attacker-controlled ones.
- For changes to the WAF data flow (anything in `wasm/`,
  `packages/core/src/transaction.ts`, `packages/core/src/wasm.ts`, or any
  adapter's `src/index.ts`): additionally run the attack-shaped scenarios
  in `test/e2e/scenarios.spec.ts`.

**How to document**: the commit message must spell out the
security-impact answer. "No impact, pure lint fix" is fine for genuine
cosmetic changes. For anything touching request flow, include a
`Security:` or `Risk:` stanza citing which of the five questions apply.

**Reviewer duty**: if you merge a change without a security check, you
own the bypass when it's found. Reject the PR and ask for it. This is
non-negotiable.

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
6. **Static/media bypass is first-class**. The unified `ignore:` option on
   every adapter (`{ extensions, routes, methods, bodyLargerThan,
   headerEquals, match, skipDefaults }`) defaults to bypassing images, CSS,
   JS, fonts, and common static-mount routes. See
   `packages/core/src/ignore.ts`. The legacy `skip:` shape is mapped to
   `ignore:` at construction with a one-shot deprecation warning per process
   and removed at stable 0.1.
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

### Branches

- **`develop`** — integration branch. Every PR lands here first. CI
  runs (typecheck + build + unit + E2E) and the selective filter
  re-tests only the affected packages and their dependents. No npm
  publish ever happens from `develop`.
- **`main`** — stable line. Published to npm. Merges into `main` only
  after `develop` is green and a maintainer opens a PR from develop
  → main.

### The very first release

0.0.0 → 0.1.0 is cut by hand: bump the `version` field in every
publishable `packages/*/package.json`, run `pnpm -r build`, run
`pnpm -r publish --access public` against an authenticated npm scope.
No changeset needed — the initial release isn't a "change".

### Every release after that

Changesets-driven on `main`:

### What you MUST do per PR

1. If the PR touches `packages/*/src/**`, `packages/*/package.json`, or
   `packages/*/tsup.config.ts`, run `pnpm changeset` locally and commit
   the generated `.changeset/*.md` file.
2. Pick the bump per package:
   - **patch** — bug fix with no public API change.
   - **minor** — new option, new adapter API, new behavior,
     security-impacting change that users want to see in the
     changelog (even if logically "a fix").
   - **major** — reserved. Pre-1.0 we use minor for everything that
     would otherwise be major; we exit 0.x by tagging `1.0.0` when
     the API surface is genuinely stable.
3. If the change is a pure internal refactor that legitimately should
   not release, commit an **empty changeset** (`pnpm changeset`, press
   Return without selecting any package) so intent is explicit. Or
   add the `skip-changeset` label if justified in the PR description.

### What CI enforces

- `changeset-check.yml` fails the PR if publishable code changed but no
  new `.changeset/*.md` file is present.
- `ci.yml` runs typecheck + build + unit tests + coverage gates + E2E
  per adapter on every PR.
- `release.yml` runs typecheck + build + unit tests on push-to-main
  *before* calling the Changesets action. A broken merge to `main` will
  block publish; it cannot accidentally escape to npm.

### What the workflows do

- `release.yml` — on push-to-main: if pending changesets exist, maintain
  a "Version Packages" PR that aggregates them. Merging that PR bumps
  versions, cascades internal-dependency bumps (see below), tags, and
  publishes to npm.
- `docs.yml` — on push-to-main: if anything under `docs/**` changed,
  republish the static site to GitHub Pages. No manual step.
- `upstream-bump.yml` — nightly: poll coraza + coraza-coreruleset
  releases, rebuild WASM, open a PR with the bump + a changeset. The
  maintainer (or agent) reviews and merges.

### Cross-package version cascading

`.changeset/config.json` sets `updateInternalDependencies: "minor"`.
That means: a minor bump to `@coraza/core` also minor-bumps every
adapter (`@coraza/express`, `@coraza/fastify`, `@coraza/next`,
`@coraza/nestjs`) because they peer-depend on it. You do NOT need to
write four changesets — one on core is enough.

`@coraza/coreruleset` and `@coraza/core` otherwise version
**independently**. CRS bumps don't cascade to adapters, and vice versa.

### Do not

- Do not run `pnpm publish` manually. Everything goes through the
  release PR flow.
- Do not commit a `.changeset/*.md` that claims a bump type that
  contradicts the code (e.g. a breaking API change marked `patch`). The
  audit trail is the changelog itself — keep it honest.
- Do not bypass `changeset-check.yml` without a tracked reason. The
  `skip-changeset` label exists for docs-only / workflow-only PRs that
  somehow touched `packages/` (rare; usually means the PR is mis-scoped).

## FTW (CRS regression corpus)

We drive the OWASP `coreruleset` `go-ftw` test corpus against every
adapter, not just Express. The goal is a fast-feedback regression
signal whenever the WASM engine or the SecLang CRS profile in
`@coraza/coreruleset` changes — either direction should show up as a
matrix-leg failure, not a silent bypass.

How the pieces fit:

- Every example app in `examples/` reads `FTW=1` from the env. When
  set, it mounts a single echo-all route, runs CRS in `block` mode at
  paranoia 2, and otherwise preserves its normal request/response
  shape. Shared logic lives in `examples/shared/src/index.ts`
  (`ftwModeEnabled`, `ftwEcho`).
- `testing/ftw/run.sh` is the runner. It installs `go-ftw` pinned via
  `GO_FTW_VERSION` (default `v2.1.1`), fetches the CRS corpus at
  `CRS_TAG` (read from `wasm/version.txt`), boots the selected
  adapter under `FTW=1`, runs `go-ftw run` with the shared overrides
  file, and enforces a pass-rate threshold.
- `testing/ftw/ftw-overrides.yaml` is shared across adapters. Entries
  carry tagged justifications — `[next-only]`, `[apache]`,
  `[node-http]`, `[upstream-coraza]`, `[engine]`, `[fastify-*]` — that
  distinguish framework-specific caveats (e.g. Next middleware cannot
  read response bodies, so the outbound RESPONSE-95x rules never fire
  there) from genuine engine bugs.
- `.github/workflows/ftw.yml` runs a `strategy.matrix` over
  `[express, fastify, next, nestjs]` with `fail-fast: false`. Express,
  Fastify, and NestJS carry a 100% threshold. Next's leg carries a
  lower threshold (85%) because its middleware runtime cannot inspect
  response bodies — the delta equals the `[next-only]` override
  block.

Running locally against a single adapter:

```sh
pnpm wasm                                      # or download an artifact
pnpm turbo run build --filter=!@coraza/example-*
bash testing/ftw/run.sh --adapter express --port 3001
# or: bash testing/ftw/run.sh fastify 3002 --threshold 98
```

If you add a rule-family override: include the tag (`[next-only]`,
`[engine]`, …) and a one-line reason. Overrides without a tag are
reviewer-rejected — the audit trail in the YAML is how we know whether
a failure is framework noise or an engine regression.

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
| WAF bypass / `ignore:` semantics | `packages/core/src/ignore.ts` (NOT per-adapter). Legacy `skip:` shape lives in `skip.ts` for one-preview back-compat and is mapped via `skipToIgnore`. |
| CRS profile preset | `packages/coreruleset/src/index.ts` |
| Bundler/framework compat case | `testing/matrix/cases/<name>/` + register in `.github/workflows/matrix.yml` and `scripts/run-local.sh` |
| Cross-OS / npm+yarn / tarball CI | `.github/workflows/{matrix,bench,tarball-smoke}.yml` (cross-OS runners, bench gate, npm/yarn legs, tarball smoke) |
| Example app (Express/Fastify/Next15/Next16/NestJS) | `examples/<name>-app/` — every app implements the shared HTTP contract from `examples/shared/` |
| CI / release workflow | `.github/workflows/*.yml` |
| Bundler / framework matrix (workspace install) | `testing/matrix/cases/*` + `.github/workflows/matrix.yml` |
| Package-manager matrix (tarball install) | `testing/matrix/pm-consumers/*` + `.github/workflows/matrix-pkg-managers.yml` |
| FTW corpus / overrides | `testing/ftw/*` + `.github/workflows/ftw.yml` |
| Docs an agent will read | THIS FILE. Not a new doc. |

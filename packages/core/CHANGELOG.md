# @coraza/core

## 0.1.0-preview.2

### Patch Changes

- 9f93ddc: Stop shipping `.d.cts` declaration files. tsup emits them with ESM
  `import` syntax inside a `.cts` extension; Turbopack 16's package
  scanner rejects this with "Specified module format (CommonJs) is not
  matching the module format of the source code (EcmaScript Modules)"
  and refuses to build any consumer that has the package in
  `node_modules`.

  `exports.types` in every package already points only at `.d.ts`,
  which TypeScript resolves under both `nodenext` and `bundler`
  moduleResolution for type-only imports — so the `.d.cts` files were
  dead weight that only triggered false-positives.

  Surfaced by the new bundler/runtime compatibility matrix exercising
  Next 16 + Turbopack against tarballs installed via npm/yarn/pnpm.

- 86cf133: Document `buildSkipPredicate` / `SkipOptions` extension match semantics on the
  type itself (case-insensitive, query/fragment ignored, only the trailing
  basename segment matches) and add support for **compound extensions**.

  Entries containing a dot (e.g. `'tar.gz'`, `'min.js'`, `'d.ts'`) now match as a
  `.<ext>` suffix on the path's basename. The leading `.` is required, so
  `extensions: ['min.js']` skips `/bundle.min.js` but **does not** skip a request
  whose pathname is literally `/min.js` (that's the bare filename, not a
  `.min.js` extension). Single-token entries (`'css'`, `'png'`) keep their
  existing behavior.

  Closes #28.

- 43602af: Default WASM loader now falls back through `createRequire` when the host
  bundler rewrites `import.meta.url` to an empty or sentinel value. Fixes
  `createWAF()` / `createWAFPool()` throwing `unsupported URL protocol:` at
  boot under Next.js 15's middleware bundler. The same fallback applies to
  the pool's `pool-worker.mjs` resolution. Behaviour is unchanged on
  runtimes that expose a usable `import.meta.url` (every non-bundled Node
  process, Next 16's `proxy.ts` pipeline, plain workers).
- f59ec36: Resolve `URL` instances by duck-typing instead of `instanceof URL` and pre-convert
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

## 0.1.0-preview.1

### Patch Changes

- 7e1232b: `WAFPool`: ship the worker file as `pool-worker.mjs` so Node unambiguously
  loads it as ESM regardless of what the surrounding bundler does with
  `package.json` markers. Fixes a silent hang under Next.js 16 Turbopack
  dev mode where the emitted worker was `.js` with ESM `import` statements
  but no sibling `"type":"module"` — Node refused to load it, the worker
  never signalled ready, and `createWAFPool` awaited forever
  (github.com/coraza-incubator/coraza-node#8).

  Also adds a `readyTimeoutMs` option to `createWAFPool` (default `10000`
  ms): if every worker has not acknowledged the init handshake within the
  window, the promise rejects with an actionable error that names the
  likely bundler / module-format cause. No more hang-forever.

  Public shape: `pool-worker.js` is no longer emitted — adapter callers
  never reference it directly, but any external tooling that expected
  `@coraza/core/dist/pool-worker.js` should switch to `pool-worker.mjs`.

- 8d1955d: Document the two CRS 4.24.0 `920640` test cases (`920640-4`, `920640-5`) as
  FTW overrides under a new `[upstream-crs]` tag. Both tests are flagged by the
  CRS corpus itself as "doesn't work with HTTP/1.1" (see the test YAML's own
  description) and can only pass under HTTP/2, where go-ftw can send a
  data-frame-length-encoded body independent of `Content-Length`. Investigation
  of the Coraza `v3.3.3 → v3.7.0` diff confirmed the engine behaves identically
  on these scenarios; the rule was newly introduced in CRS 4.24.0 so there was
  no previous baseline to "regress" against. Verified with a standalone Go
  reproducer running the full CRS stack on both engine versions.

  Also bumps the pinned upstream versions on this branch to match `main`:
  `coraza=3.7.0`, `coreruleset=4.25.0`.

- 8297b66: Bumped upstream: coraza=3.7.0,
  coreruleset=4.25.0. Rebuilt WASM.

## 0.1.0-preview.0

### Minor Changes

- fde87b5: Initial public preview. OWASP Coraza WAF for Node.js, compiled to
  WebAssembly via TinyGo. Adapters for Express, Fastify, Next.js,
  NestJS share a common option shape (`coraza({ waf, onBlock?, onWAFError?,
skip?, inspectResponse? })`) and accept both a built WAF and a
  `Promise<WAF | WAFPool>`. Core ships `createWAF` (sync, single-thread)
  and `createWAFPool` (worker_threads, N× scale) with per-worker
  rotation (`maxRequestsPerWorker`) to cap long-term memory. Full
  OWASP CoreRuleSet is embedded in the WASM binary; `@coraza/coreruleset`
  exposes ergonomic preset helpers.

  Verified: 100% CRS conformance via go-ftw across all four adapters
  (3869/3869 tests pass, 22 ignored-with-justification against
  Apache/Node-http surface differences). Hardened CI with per-package
  matrix (Node 22 + 24), SHA-pinned actions, weekly k6 regression
  bench. Known inbound-only adapters: Next and NestJS (framework
  limitations, documented).

  See README and https://coraza-incubator.github.io/coraza-node for the full
  guide.

- c8cdd9e: perf(core): tighten `env.rx_match` host import for V8 fast-call

  - `wasm.ts` caches a live-bound `Buffer` over the WASM linear memory,
    invalidated when `memory.buffer` identity changes (WASM
    `memory.grow`). `rx_match` now decodes via
    `buf.toString('utf8', start, end)` — a direct C++ path — instead of
    rebuilding a `Uint8Array` view and round-tripping through
    `TextDecoder.decode(subarray(...))` on every call.
  - `hostRegex.ts` adds a per-handle move-to-front LRU of size 8 over
    `(handle, input) -> matched`. CRS paranoia-2 fires a cascade of
    `@rx` rules against the same ARGS value; the LRU collapses repeated
    evaluations of the same pair to a single regex test.

  Observable behaviour is unchanged: same boolean return, same
  `host_regex` capture semantics, same fail-closed on compile error
  (Go falls back to stdlib regex for PCRE-only features).

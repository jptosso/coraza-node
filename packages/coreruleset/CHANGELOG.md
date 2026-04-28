# @coraza/coreruleset

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

## 0.1.0-preview.1

### Patch Changes

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

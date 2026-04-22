# @coraza/next

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

### Patch Changes

- Updated dependencies [fde87b5]
- Updated dependencies [c8cdd9e]
  - @coraza/core@0.1.0-preview.0

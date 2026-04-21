# @coraza/core

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

  See README and https://jptosso.github.io/coraza-node for the full
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

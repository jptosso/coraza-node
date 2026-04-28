# @coraza/fastify

## 0.1.0-preview.3

### Patch Changes

- 3cf763a: Unify request-bypass configuration under a single `ignore:` field on every
  adapter. `IgnoreSpec` covers extensions, glob/regex routes, HTTP methods,
  body-size cutoffs (`bodyLargerThan` -> `'skip-body'` verdict), header
  equality, and an imperative `match` escape hatch. Verdicts merge with
  `false > 'skip-body' > true` (most-restrictive wins, fail-closed).

  The legacy `skip:` option is soft-deprecated for one preview: it's mapped
  to the equivalent `ignore:` shape at adapter construction and emits a
  one-shot deprecation warning per process. Removed at stable 0.1.

  Security: no new bypass shapes — every existing default (extension list +
  built-in static-mount routes like `/_next/static/*`) is preserved. Errors
  in user-supplied `match` predicates are caught and treated as `false`
  (inspect normally) so a buggy predicate cannot become a bypass.

- Updated dependencies [3cf763a]
  - @coraza/core@0.1.0-preview.3

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

- Updated dependencies [9f93ddc]
- Updated dependencies [86cf133]
- Updated dependencies [43602af]
- Updated dependencies [f59ec36]
  - @coraza/core@0.1.0-preview.2

## 0.1.0-preview.1

### Patch Changes

- Updated dependencies [7e1232b]
- Updated dependencies [8d1955d]
- Updated dependencies [8297b66]
  - @coraza/core@0.1.0-preview.1

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

- 716fa6b: fix(fastify): skip `inspectResponse` under a pool'd WAF

  Under `createWAFPool` the `onSend` hook's async round-trip to a
  worker races Fastify's reply-write path; a block verdict from the
  response phase then calls `reply.code(...)` after headers have been
  committed and crashes the process with `ERR_HTTP_HEADERS_SENT`.
  Mirrors the Express adapter: when `inspectResponse: true` is set on
  a pool'd WAF we now log a single warning at register time and skip
  the response hook entirely. Request-phase (phases 1 + 2) inspection
  is unaffected; the fail-closed `onWAFError: 'block'` default still
  applies.

- Updated dependencies [fde87b5]
- Updated dependencies [c8cdd9e]
  - @coraza/core@0.1.0-preview.0

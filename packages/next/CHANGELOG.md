# @coraza/next

## 0.1.0-preview.5

### Patch Changes

- 485327a: Surface contributing rules in the block log. The default block-log line
  now includes `interruption.data` (the WAF has already populated it — for
  CRS this is the human-readable reason, e.g. `Inbound Anomaly Score
Exceeded (Total Score: 10)`). A new `verboseLog?: boolean` option emits
  one `coraza: matched` line per contributing rule and exposes the matched
  rules to a custom `onBlock` via an optional `ctx.matchedRules` argument.
  Default is `false`; opting in costs one extra `tx.matchedRules()`
  round-trip per block. Closes #23.

## 0.1.0-preview.4

### Patch Changes

- 054d1c0: Add `inspectBody?: boolean` (default `true`) on `@coraza/next`. When
  `false`, the runner skips `req.arrayBuffer()` entirely — the request
  body reaches the route handler untouched, body-targeted CRS rules
  (`ARGS_POST`, `REQUEST_BODY`) cannot fire, but URL/header/cookie rules
  and the phase-2 anomaly evaluator still run. Documented as a security
  trade-off in the README "Body handling" section, alongside the
  runtime-version compatibility notes for body re-injection. Closes #26.

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

- f59ec36: Tighten peer-dep ranges to the set the matrix actually exercises:

  - `@coraza/next` peer: `^15.0.0 || ^16.0.0` (was `^14.0.0 || ^15.0.0 || ^16.0.0`).
    Next 14 middleware is **edge-runtime only** — `experimental.nodeMiddleware` did
    not land until Next 15 — so `@coraza/next`'s Node-runtime adapter cannot work
    there. Removing 14 from the peer range so `pnpm add @coraza/next` no longer
    tells Next 14 users they're supported when they aren't.

  - `@coraza/nestjs` peer: `^11.0.0` (was `^10.0.0 || ^11.0.0`). NestJS 10's
    `ExceptionsHandler` does an `instanceof HttpException` check that fails when
    the exception is constructed from `@coraza/nestjs`'s own `@nestjs/common@11`
    copy under pnpm's strict resolution, returning a generic 500 instead of the
    guard's intended 403. NestJS 11 has been out for over a year; pinning to it
    removes a confusing failure mode.

  This is a documentation correction more than a behavior change — the previous
  ranges were aspirational, not validated. The compatibility matrix
  (`testing/matrix/`) now exercises every supported combination on every PR.

- 43602af: Documentation: rewrite the README version/runtime/WASM-loader table to
  accurately describe Next 14 / 15 / 16. Add a "Known bundler quirks"
  section pointing at the `@coraza/core` `createRequire` fallback that
  makes Next 15 middleware work without a manual `wasmSource` override.
  Link the `examples/next15-app` and `examples/next16-app` demos. No
  runtime API change.
- Updated dependencies [9f93ddc]
- Updated dependencies [86cf133]
- Updated dependencies [43602af]
- Updated dependencies [f59ec36]
  - @coraza/core@0.1.0-preview.2

## 0.1.0-preview.1

### Patch Changes

- a7941a4: Widen Next.js peer-dep to accept `^16.0.0`. Next 16 is now the current major
  (latest 16.2.4); the middleware contract used by `@coraza/next` is unchanged,
  and the existing unit + E2E test suite passes against 16 with no code changes.
  The adapter now declares `next: ^14 || ^15 || ^16`, covering every Next major
  in active use.
- 7e1232b: Add `createCorazaRunner` — a factory returning a WAF evaluator with a
  structured decision (`{ blocked: Response } | { allow: true }`) so apps
  with an existing `proxy.ts` (auth, redirects, etc.) can compose Coraza
  with their own logic without sniffing the `x-middleware-next` response
  header (internal territory). See the "Composing with an existing
  `proxy.ts`" section of the adapter README for the canonical pattern.

  The existing `coraza(opts)` middleware helper is now a thin wrapper
  around `createCorazaRunner` and keeps its previous signature and
  behaviour.

- 7e1232b: Docs: update the README for Next.js 16 and `src/` layout —

  - Drop `runtime: 'nodejs'` from the `config` export; Next 16 rejects the
    option outright in `proxy.ts` (`The runtime config option is not
available in Proxy files`) and it's redundant on 14/15 because Node is
    already the default.
  - Show both filenames side-by-side (`proxy.ts` on Next 16, `middleware.ts`
    on 14/15) with a short note so the snippet is copy-pasteable on every
    current major.
  - Add a "File location" paragraph warning that with a `src/` layout,
    the adapter file **must** live at `src/proxy.ts` / `src/middleware.ts`
    — a file at the repo root is silently ignored (Next emits no logs).
  - Document the Turbopack pool-worker hazard and point at the new
    `readyTimeoutMs` fail-fast (see the `@coraza/core` changeset).

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

- Updated dependencies [fde87b5]
- Updated dependencies [c8cdd9e]
  - @coraza/core@0.1.0-preview.0

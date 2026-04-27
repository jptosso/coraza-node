# pm-consumers — package-manager × adapter consumer templates

These directories are **not** workspace packages. They are templates the
`matrix-pkg-managers.yml` workflow copies into a freshly-`<pm> init -y`'d
consumer project to verify that the **published** `@coraza/*` tarballs
resolve and run cleanly under npm, yarn (4 / Berry), and pnpm.

The matrix in `testing/matrix/cases/` only proves things work under pnpm
(the workspace's own package manager). pnpm's strict, symlinked
`node_modules` differs materially from npm's and yarn's flat hoisting.
Peer-dep duplication, `instanceof` mismatches across two copies of a
transitive dep, missing peer-dep auto-install — none of those would
surface in the existing matrix.

## How a leg runs

1. `pnpm pack` every publishable package (`core`, `coreruleset`, `express`,
   `fastify`, `nestjs`, `next`) into `/tmp/coraza-tarballs/`.
2. The workflow `mkdir`s a fresh consumer dir outside the repo.
3. `<pm> init -y` is run. For yarn we additionally
   `corepack enable && yarn set version stable` (Yarn 4).
4. The full set of tarballs is installed:
   - `npm install <tarball>...`
   - `yarn add <tarball>...` (Yarn 4)
   - `pnpm add <tarball>...`
   plus the framework dependency (`express@5`, `fastify@5`, `next@16`,
   `@nestjs/common`+`@nestjs/core`+`@nestjs/platform-express`+`reflect-metadata`+`rxjs`).
5. The matching template directory is copied in.
6. The server is booted with `tsx server.ts` (or `node server.mjs` for
   `plain-esm`) on `$PORT`.
7. `testing/matrix/scripts/check.mjs` fires the three-scenario probe:
   `/healthz` → 200, `/search?q=<SQLi>` → 403, `POST /echo {msg:<XSS>}`
   → 403.

## Constraints on these templates

- **No `workspace:*` references.** They install from real tarballs, the
  same way an end user would.
- **No relative paths into the repo.** `wasmSource` is omitted so the
  loader resolves the asset via `@coraza/core/dist/wasm/coraza.wasm`,
  which is the path bundlers and end users hit.
- **One source file per case.** Anything more complex (Next's app
  router, Nest module wiring) lives in subdirs but the entry point
  remains a single root file.
- **Mirror the `testing/matrix/cases/<case>/` shape.** The check.mjs
  contract is the same — drift between the two would be a regression
  trap.

If you find a package-manager-specific bug while iterating locally, do
not paper over it in these templates. The point is to *surface* the
bug. Add a workflow-level comment explaining the failure and report
upstream.

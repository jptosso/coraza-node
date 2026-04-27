---
'@coraza/core': patch
'@coraza/coreruleset': patch
'@coraza/express': patch
'@coraza/fastify': patch
'@coraza/nestjs': patch
'@coraza/next': patch
---

Stop shipping `.d.cts` declaration files. tsup emits them with ESM
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

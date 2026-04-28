---
'@coraza/core': patch
'@coraza/express': patch
'@coraza/fastify': patch
'@coraza/nestjs': patch
'@coraza/next': patch
---

Unify request-bypass configuration under a single `ignore:` field on every
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

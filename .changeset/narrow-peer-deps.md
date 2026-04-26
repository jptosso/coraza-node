---
'@coraza/next': patch
'@coraza/nestjs': patch
---

Tighten peer-dep ranges to the set the matrix actually exercises:

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

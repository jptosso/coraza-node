---
'@coraza/next': patch
---

Widen Next.js peer-dep to accept `^16.0.0`. Next 16 is now the current major
(latest 16.2.4); the middleware contract used by `@coraza/next` is unchanged,
and the existing unit + E2E test suite passes against 16 with no code changes.
The adapter now declares `next: ^14 || ^15 || ^16`, covering every Next major
in active use.

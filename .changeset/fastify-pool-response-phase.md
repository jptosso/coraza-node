---
'@coraza/fastify': patch
---

fix(fastify): skip `inspectResponse` under a pool'd WAF

Under `createWAFPool` the `onSend` hook's async round-trip to a
worker races Fastify's reply-write path; a block verdict from the
response phase then calls `reply.code(...)` after headers have been
committed and crashes the process with `ERR_HTTP_HEADERS_SENT`.
Mirrors the Express adapter: when `inspectResponse: true` is set on
a pool'd WAF we now log a single warning at register time and skip
the response hook entirely. Request-phase (phases 1 + 2) inspection
is unaffected; the fail-closed `onWAFError: 'block'` default still
applies.

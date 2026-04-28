---
'@coraza/next': patch
'@coraza/express': patch
'@coraza/fastify': patch
'@coraza/nestjs': patch
---

Extend `onWAFError` to accept a per-error policy function. The runner
tracks `consecutiveErrors` (resets on the next successful WAF
evaluation), `totalErrors` (process-lifetime), and `since` (timestamp
of the first error in the current consecutive run). Pass a function
`(err, ctx) => 'allow' | 'block'` to implement circuit-breaker / rate
/ per-error-class policy without `@coraza/{adapter}` enforcing one
opinion. The string forms (`'allow'`, `'block'`, default `'block'`)
remain unchanged. A throwing policy function falls back to `'block'`
(fail-closed). No default circuit breaker is added — consumers get
the data and write the policy. Closes #29.

---
'@coraza/next': patch
'@coraza/express': patch
'@coraza/fastify': patch
'@coraza/nestjs': patch
---

Surface contributing rules in the block log. The default block-log line
now includes `interruption.data` (the WAF has already populated it — for
CRS this is the human-readable reason, e.g. `Inbound Anomaly Score
Exceeded (Total Score: 10)`). A new `verboseLog?: boolean` option emits
one `coraza: matched` line per contributing rule and exposes the matched
rules to a custom `onBlock` via an optional `ctx.matchedRules` argument.
Default is `false`; opting in costs one extra `tx.matchedRules()`
round-trip per block. Closes #23.

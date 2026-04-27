---
'@coraza/next': patch
'@coraza/express': patch
'@coraza/fastify': patch
'@coraza/nestjs': patch
---

Surface the original error when the WAF promise rejects. New
`onWAFInit?: (err: Error) => void` option fires once with the original
boot-time error (WASM compile failure, ABI mismatch, OOM) so external
healthchecks / loggers can capture the stack before request handling
even runs. The per-request error log on a permanently-broken WAF now
carries the original message + stack instead of collapsing to "WAF
unavailable", and the synthesized 503 `Interruption.data` reads
`WAF init failed: <message>` so operators can see the real cause in
access logs. Also documented in the `@coraza/next` README. Closes #25.

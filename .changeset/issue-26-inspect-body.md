---
'@coraza/next': patch
---

Add `inspectBody?: boolean` (default `true`) on `@coraza/next`. When
`false`, the runner skips `req.arrayBuffer()` entirely — the request
body reaches the route handler untouched, body-targeted CRS rules
(`ARGS_POST`, `REQUEST_BODY`) cannot fire, but URL/header/cookie rules
and the phase-2 anomaly evaluator still run. Documented as a security
trade-off in the README "Body handling" section, alongside the
runtime-version compatibility notes for body re-injection. Closes #26.

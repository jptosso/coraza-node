---
'@coraza/next': patch
---

Add `createCorazaRunner` — a factory returning a WAF evaluator with a
structured decision (`{ blocked: Response } | { allow: true }`) so apps
with an existing `proxy.ts` (auth, redirects, etc.) can compose Coraza
with their own logic without sniffing the `x-middleware-next` response
header (internal territory). See the "Composing with an existing
`proxy.ts`" section of the adapter README for the canonical pattern.

The existing `coraza(opts)` middleware helper is now a thin wrapper
around `createCorazaRunner` and keeps its previous signature and
behaviour.

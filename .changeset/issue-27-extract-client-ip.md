---
'@coraza/next': patch
---

Add `extractClientIp?: (req: NextRequest) => string` on `@coraza/next`.
The previous behaviour — first hop of `X-Forwarded-For` — is the new
default (no regression), exposed as `defaultExtractClientIp`. Override
it to support Cloudflare (`cf-connecting-ip`), AWS ALB / Nginx default
(last hop of XFF), or direct-exposure topologies. Without correct IP
extraction, CRS IP-based rules (REQUEST-913, IP allowlist/blocklist)
are advisory at best — README "Client IP extraction" section spells
this out for each common topology. Closes #27.

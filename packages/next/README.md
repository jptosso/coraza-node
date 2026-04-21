# @coraza/next

Next.js middleware adapter for [coraza-node](https://github.com/jptosso/coraza-node).
Node runtime only — the Edge runtime lacks WASI.

```ts
// middleware.ts
import os from 'node:os'
import { createWAFPool } from '@coraza/core'
import { coraza } from '@coraza/next'
import { recommended } from '@coraza/coreruleset'

const waf = createWAFPool({
  rules: recommended(),
  mode: 'block',
  size: os.availableParallelism(),
})

export const middleware = coraza({ waf })
export const config = { matcher: '/:path*', runtime: 'nodejs' }
```

### Limitation — no response-body inspection

Next middleware runs on the request boundary. Route Handlers own the
`Response`, and Next's runtime doesn't hand the response body back to
middleware, so CRS's `RESPONSE-95*-DATA-LEAKAGES-*` families can't fire
on a Next deployment. Inbound protection (SQLi, XSS, RCE, LFI, RFI,
scanner-detection, protocol-attack, anomaly scoring) works identically
to every other adapter. If you need response-body inspection, put
Express or Fastify in front of Next and run coraza-node there.

> **Experimental.** Independent community project, not an official
> OWASP / Coraza release.

Docs: <https://jptosso.github.io/coraza-node#api-next>
· License: Apache-2.0

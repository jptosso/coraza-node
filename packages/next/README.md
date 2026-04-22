# @coraza/next

Next.js middleware adapter for [coraza-node](https://github.com/coraza-incubator/coraza-node).
Node runtime only — the Edge runtime lacks WASI.

## Quick start

```ts
// Next 16+:   src/proxy.ts          (file renamed in Next 16)
// Next 14/15: src/middleware.ts     (or middleware.ts at repo root)
import { createWAF } from '@coraza/core'
import { coraza } from '@coraza/next'
import { recommended } from '@coraza/coreruleset'

const waf = createWAF({ rules: recommended(), mode: 'block' })

// Pick the export name that matches your filename:
//   `proxy.ts`      → export const proxy
//   `middleware.ts` → export const middleware
export const proxy = coraza({ waf })

export const config = { matcher: '/:path*' }
```

> **Next 16:** do **not** set `runtime: 'nodejs'` on the `config` export —
> Next 16's `proxy.ts` defaults to the Node.js runtime and rejects the
> option outright (`The runtime config option is not available in Proxy
> files`). On Next 14/15 the option is accepted but also unnecessary
> because Node is the default for `middleware.ts`.

### File location (important with `src/` layout)

With a `src/` directory, Next 16 **only** picks up `src/proxy.ts` — a
file at the repo root is silently ignored and the adapter runs zero code
(no logs). Mirror the convention of your `app/` directory:

- `src/` layout → `src/proxy.ts` (or `src/middleware.ts` on 14/15)
- Flat layout → `proxy.ts` at the project root

### Threaded pool under Turbopack dev (Next 16)

`createWAFPool` spawns `node:worker_threads` and loads a `.mjs` file for
the worker body so Node always treats it as an ES module, regardless of
what the bundler does around it. If the pool ever fails to come up, the
`createWAFPool` promise rejects within `readyTimeoutMs` (default 10 s)
with an actionable error — no more silent hangs.

If you still hit bundler trouble, fall back to `createWAF`
(single-threaded) — it works identically from the adapter's perspective:

```ts
const waf = createWAF({ rules: recommended(), mode: 'block' })
export const proxy = coraza({ waf })
```

### Composing with an existing `proxy.ts`

If your app already has a `proxy.ts` (auth gating, redirects, locale
routing, etc.), use `createCorazaRunner` to get a structured decision
back and fall through on allow:

```ts
// src/proxy.ts
import { createWAF } from '@coraza/core'
import { createCorazaRunner } from '@coraza/next'
import { recommended } from '@coraza/coreruleset'
import { NextResponse, type NextRequest } from 'next/server'

const waf = createWAF({ rules: recommended(), mode: 'block' })
const runCoraza = createCorazaRunner({ waf })

export async function proxy(req: NextRequest) {
  // 1. Coraza first — block attackers before any app code sees them.
  const decision = await runCoraza(req)
  if ('blocked' in decision) return decision.blocked

  // 2. Your existing logic on allow.
  if (!req.cookies.get('session')) {
    return NextResponse.redirect(new URL('/login', req.url))
  }
  return NextResponse.next()
}

export const config = { matcher: '/:path*' }
```

`createCorazaRunner` returns `{ blocked: Response } | { allow: true }`.
The `blocked` branch must be returned unchanged — post-processing a
block defeats the WAF. This is the supported public API; sniffing
`x-middleware-next` on a response is internal and not supported.

### Limitation — no response-body inspection

Next middleware / proxy runs on the request boundary. Route Handlers own
the `Response`, and Next's runtime doesn't hand the response body back
to the proxy, so CRS's `RESPONSE-95*-DATA-LEAKAGES-*` families can't
fire on a Next deployment. Inbound protection (SQLi, XSS, RCE, LFI, RFI,
scanner-detection, protocol-attack, anomaly scoring) works identically
to every other adapter. If you need response-body inspection, put
Express or Fastify in front of Next and run coraza-node there.

> **Experimental.** Independent community project, not an official
> OWASP / Coraza release.

Docs: <https://coraza-incubator.github.io/coraza-node#api-next>
· License: Apache-2.0

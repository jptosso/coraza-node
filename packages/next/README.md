# @coraza/next

Next.js middleware adapter for [coraza-node](https://github.com/coraza-incubator/coraza-node).
Node runtime only — the Edge runtime lacks WASI.

## Supported versions

| Next | File            | Runtime opt-in    | WASM loader path |
| ---- | --------------- | ----------------- | ---------------- |
| 15   | `middleware.ts` | `runtime:'nodejs'`| Next 15's middleware bundler rewrites `import.meta.url` to a sentinel; `@coraza/core` falls back through `createRequire` automatically. No user action. |
| 16   | `proxy.ts`      | none — rejected   | `import.meta.url` is preserved; default path works directly. |

Peer-deps: `next: ^15 || ^16`. Next 14 is intentionally unsupported —
its middleware ran on the Edge runtime by default, which lacks WASI and
cannot host the Coraza WASM.

Example apps in this repo covering both filename conventions:

- [`examples/next15-app/`](../../examples/next15-app/) — Next 15 + `middleware.ts`.
- [`examples/next16-app/`](../../examples/next16-app/) — Next 16 + `proxy.ts`.

## Quick start

```ts
// Next 16: src/proxy.ts             (file renamed in Next 16)
// Next 15: src/middleware.ts        (or middleware.ts at repo root)
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
> files`). On Next 15 the option is accepted and required to pin
> middleware off the Edge runtime.

## Known bundler quirks

- **Next 15 rewrites `import.meta.url` in middleware.** Previously this
  made `createWAF()` throw `unsupported URL protocol:` at boot.
  `@coraza/core` now catches that and falls back to
  `createRequire(import.meta.url).resolve('@coraza/core/package.json')`
  to locate the shipped WASM, which Node resolves irrespective of what
  the bundler did to `import.meta.url`. The same fallback covers
  `pool-worker.mjs` for `createWAFPool`. No code change required in
  your `middleware.ts`.
- **Turbopack + threaded pool (Next 16 dev mode).** `createWAFPool`
  emits a `.mjs` worker so Node always treats it as ESM even when
  Turbopack re-emits chunks without the `"type":"module"` marker. If
  the pool ever fails to initialize, `createWAFPool` rejects within
  `readyTimeoutMs` (default 10 s) with an actionable error. Fall back
  to `createWAF` (single-threaded) if you hit this.

### File location (important with `src/` layout)

With a `src/` directory, Next 16 **only** picks up `src/proxy.ts` — a
file at the repo root is silently ignored and the adapter runs zero code
(no logs). Mirror the convention of your `app/` directory:

- `src/` layout → `src/proxy.ts` (or `src/middleware.ts` on 14/15)
- Flat layout → `proxy.ts` at the project root

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

## Skipping the WAF

Pass `ignore:` to declare which requests bypass Coraza. Every field is
optional and may be combined.

| Field            | Type                                | Example                                       |
| ---------------- | ----------------------------------- | --------------------------------------------- |
| `extensions`     | `string[]`                          | `['css','js','min.js']`                       |
| `routes`         | `(string \| RegExp)[]`              | `['/static/*', /^\/internal\//]`              |
| `methods`        | `string[]`                          | `['OPTIONS','HEAD']`                          |
| `bodyLargerThan` | `number` (bytes)                    | `10_000_000`                                  |
| `headerEquals`   | `Record<string, string \| string[]>` | `{ 'x-internal': 'true' }`                    |
| `match`          | `(ctx) => boolean \| 'skip-body'`   | custom predicate, sync only                   |
| `skipDefaults`   | `boolean`                           | `true` to drop the built-in extension list    |

Verdicts: `false` (inspect), `true` (skip everything), `'skip-body'`
(inspect URL + headers, skip the body phase). When both declarative
rules and `match` produce a verdict, **most-restrictive wins**:
`false > 'skip-body' > true`.

The legacy `skip:` option is deprecated and mapped to `ignore:` at
construction (one-shot warning per process). It will be removed at
stable 0.1.

### Body handling

The runner reads the request body via `req.arrayBuffer()` before
forwarding to your route handler. On Next 16 (`proxy.ts`) the runtime
buffers the request and the route handler can still call `req.json()`
or `req.formData()` against its own copy. We test against Next 16.x;
older versions or runtimes that don't re-inject the body MAY break
downstream parsers — symptom is `Unexpected end of JSON input` from
your route handler with no Coraza log line.

If body re-injection isn't reliable on your runtime, OR you want
WAF on headers/URL only (a common false-positive reduction), opt out:

```ts
export const proxy = coraza({ waf, inspectBody: false })
```

`inspectBody: false`:
- Skips `req.arrayBuffer()` entirely; body reaches your route handler
  untouched.
- Disables body-targeted CRS rules (`ARGS_POST`, `REQUEST_BODY`) —
  most XSS and many SQLi attacks won't be detected.
- Still runs URL + header + cookie rules and the phase-2 anomaly
  evaluator on every request.

Default is `inspectBody: true`. **Flipping it off is a security
trade-off** — body-bearing attacks become invisible. Document why
you're doing it in your codebase.

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

# coraza-node

> **Experimental.** This is an independent community project, not an
> official Coraza or OWASP release. The Coraza engine itself is official;
> this Node.js packaging / adapter layer around it is not. API surface
> may change before 1.0. Author: **Juan Pablo Tosso**
> ([pablo@owasp.org](mailto:pablo@owasp.org)).

OWASP Coraza WAF for Node.js — ships as an npm package, no sidecar required.

The WAF engine ([OWASP Coraza](https://github.com/corazawaf/coraza)) is compiled
to WebAssembly via TinyGo and embedded inside each framework adapter. The
[OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset) is baked into
the WASM via [`coraza-coreruleset`](https://github.com/corazawaf/coraza-coreruleset).

- Docs site: **[coraza-incubator.github.io/coraza-node](https://coraza-incubator.github.io/coraza-node)**
- Live Express demo on Vercel: **[coraza-node-express-app.vercel.app](https://coraza-node-express-app.vercel.app/)**
  (try `?q=%27+OR+1%3D1--` to see CRS block a SQLi payload)

## Packages

| Package | Description |
| --- | --- |
| [`@coraza/core`](./packages/core) | WAF engine (loads the WASM). Framework-agnostic. |
| [`@coraza/coreruleset`](./packages/coreruleset) | CRS config helpers & presets. |
| [`@coraza/express`](./packages/express) | Express middleware. |
| [`@coraza/fastify`](./packages/fastify) | Fastify plugin. |
| [`@coraza/next`](./packages/next) | Next.js middleware adapter. |
| [`@coraza/nestjs`](./packages/nestjs) | NestJS module + guard. |

## Quick start — Express

```ts
import os from 'node:os'
import express from 'express'
import { createWAFPool } from '@coraza/core'
import { coraza } from '@coraza/express'
import { recommended } from '@coraza/coreruleset'

const app = express()
app.use(express.json())

// Pool across worker threads — the recommended shape for production.
// One WAF per CPU core, round-robin dispatch.
const waf = await createWAFPool({
  rules: recommended(),
  mode: 'block',
  size: os.availableParallelism(),
})
app.use(coraza({ waf }))

app.get('/', (_req, res) => res.json({ ok: true }))
app.listen(3000)
```

`createWAF` is available for single-core, synchronous workloads (tests,
lambdas, CLIs). For long-running HTTP servers, always use
`createWAFPool` — ~4.5× throughput on an 8-core box with the same API.

Full guide — tuning, custom block responses, fail-open/closed, detect-only
mode, per-adapter options — lives on the docs site:
**[coraza-incubator.github.io/coraza-node](https://coraza-incubator.github.io/coraza-node)**.

## Development

```sh
pnpm install
pnpm build         # builds WASM + all packages
pnpm test          # unit tests, coverage enforced
pnpm e2e           # end-to-end tests per adapter
```

## Performance

~4,857 RPS under full CRS at POOL=8, 100% attack block rate, p99 ~37 ms
under 50-VU mixed traffic. Detail + tuning knobs:
**[coraza-incubator.github.io/coraza-node#perf](https://coraza-incubator.github.io/coraza-node#perf)**.

## Adapter caveat — Next.js

Supported on Next.js 14, 15, and 16. See
[`packages/next/README.md`](./packages/next/README.md) for the
copy-pasteable `proxy.ts` (Next 16) / `middleware.ts` (Next 14/15)
snippet, the `src/` layout note, and how to compose with an existing
`proxy.ts`.

Next's middleware / proxy runs on the **request boundary only**. Route
Handlers own the `Response`, and Next's runtime doesn't expose the
response body back to middleware — that's a Next architectural choice,
not a WAF limitation. Consequence for coraza-node:

- **Inbound rules fire as usual.** URI, headers, and body inspection
  (CRS phases 1 + 2) work identically to every other adapter.
- **Outbound response-body rules don't.** The CRS `RESPONSE-95*-DATA-
  LEAKAGES-*` families (SQL errors, Java / PHP stack traces, IIS
  errors, webshell output) have no response body to match against on
  a Next deployment, and the corresponding go-ftw tests skip on the
  Next leg by design (see
  [`testing/ftw/ftw-overrides-next.yaml`](./testing/ftw/ftw-overrides-next.yaml)).

If you need response-body inspection on Next, put an Express or
Fastify service in front and run coraza-node there. The Next middleware
adapter is still useful — it catches 90%+ of what CRS flags in
practice, and the high-value inbound attacks (SQLi, XSS, RCE, LFI,
RFI) are all phase-1/phase-2.

## CRS compatibility

Measured by [go-ftw](https://github.com/coreruleset/go-ftw) against the
CRS regression corpus matching `wasm/version.txt`. Results live in
[`testing/ftw/`](./testing/ftw) and are re-run on every CI push.

## License

Apache-2.0

# coraza-node

OWASP Coraza WAF for Node.js — ships as an npm package, no sidecar required.

The WAF engine ([OWASP Coraza](https://github.com/corazawaf/coraza)) is compiled
to WebAssembly via TinyGo and embedded inside each framework adapter. The
[OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset) is baked into
the WASM via [`coraza-coreruleset`](https://github.com/corazawaf/coraza-coreruleset).

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
import express from 'express'
import { coraza } from '@coraza/express'
import { recommended } from '@coraza/coreruleset'

const app = express()
app.use(await coraza({ rules: recommended() }))
```

## Development

```sh
pnpm install
pnpm build         # builds WASM + all packages
pnpm test          # unit tests, coverage enforced
pnpm e2e           # end-to-end tests per adapter
```

## License

Apache-2.0

# @coraza/fastify

Fastify plugin for [coraza-node](https://github.com/coraza-incubator/coraza-node).

```ts
import os from 'node:os'
import Fastify from 'fastify'
import { createWAFPool } from '@coraza/core'
import { coraza } from '@coraza/fastify'
import { recommended } from '@coraza/coreruleset'

const app = Fastify()
const waf = await createWAFPool({
  rules: recommended(),
  mode: 'block',
  size: os.availableParallelism(),
})
await app.register(coraza, { waf })
```

Options: `{ waf, onBlock?, onWAFError?, ignore?, inspectResponse? }`.
Response hooks only fire with a sync `WAF` (not `WAFPool`) — pooled
adapters skip response inspection and log a warning.

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

> **Experimental.** Independent community project, not an official
> OWASP / Coraza release.

Docs: <https://coraza-incubator.github.io/coraza-node#api-fastify>
· License: Apache-2.0

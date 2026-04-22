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

Options: `{ waf, onBlock?, onWAFError?, skip?, inspectResponse? }`.
Response hooks only fire with a sync `WAF` (not `WAFPool`) — pooled
adapters skip response inspection and log a warning.

> **Experimental.** Independent community project, not an official
> OWASP / Coraza release.

Docs: <https://coraza-incubator.github.io/coraza-node#api-fastify>
· License: Apache-2.0

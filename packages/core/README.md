# @coraza/core

Core WAF engine for [coraza-node](https://github.com/coraza-incubator/coraza-node).
Loads the compiled OWASP Coraza WASM binary and exposes the
`WAF` / `WAFPool` / `Transaction` primitives that every framework adapter
builds on. Framework-agnostic — use one of the adapters
(`@coraza/express`, `@coraza/fastify`, `@coraza/next`, `@coraza/nestjs`)
unless you're writing your own.

```ts
import os from 'node:os'
import { createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'

const waf = await createWAFPool({
  rules: recommended(),
  mode: 'block',
  size: os.availableParallelism(),
})
```

> **Experimental.** Independent community project, not an official
> OWASP / Coraza release. API may change before 1.0.

Docs: <https://coraza-incubator.github.io/coraza-node>
· License: Apache-2.0

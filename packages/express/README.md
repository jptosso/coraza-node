# @coraza/express

Express middleware for [coraza-node](https://github.com/jptosso/coraza-node).

```ts
import os from 'node:os'
import express from 'express'
import { createWAFPool } from '@coraza/core'
import { coraza } from '@coraza/express'
import { recommended } from '@coraza/coreruleset'

const app = express()
app.use(express.json())

const waf = await createWAFPool({
  rules: recommended(),
  mode: 'block',
  size: os.availableParallelism(),
})
app.use(coraza({ waf }))
```

Options: `{ waf, onBlock?, onWAFError?, skip?, inspectResponse? }`.
Both request and response phases run; fails closed by default on WAF
errors (override with `onWAFError: 'allow'`).

> **Experimental.** Independent community project, not an official
> OWASP / Coraza release.

Docs: <https://jptosso.github.io/coraza-node#api-express>
· License: Apache-2.0

# @coraza/nestjs

NestJS module + guard for [coraza-node](https://github.com/jptosso/coraza-node).

```ts
// app.module.ts
import os from 'node:os'
import { Module } from '@nestjs/common'
import { createWAFPool } from '@coraza/core'
import { CorazaModule } from '@coraza/nestjs'
import { recommended } from '@coraza/coreruleset'

const waf = await createWAFPool({
  rules: recommended(),
  mode: 'block',
  size: os.availableParallelism(),
})

@Module({
  imports: [CorazaModule.forRoot({ waf })],
})
export class AppModule {}
```

Options: `{ waf, onBlock?, onWAFError?, skip?, globalGuard? }`.
Registers `CorazaGuard` as `APP_GUARD` by default. Guard runs
pre-handler, so CRS's `RESPONSE-*` rules (response-body leak
detection) aren't exercised — same inbound-only shape as Next's
middleware limitation.

> **Experimental.** Independent community project, not an official
> OWASP / Coraza release.

Docs: <https://jptosso.github.io/coraza-node#api-nestjs>
· License: Apache-2.0

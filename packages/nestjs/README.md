# @coraza/nestjs

NestJS module + guard for [coraza-node](https://github.com/coraza-incubator/coraza-node).

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

Options: `{ waf, onBlock?, onWAFError?, ignore?, globalGuard? }`.
Registers `CorazaGuard` as `APP_GUARD` by default. Guard runs
pre-handler, so CRS's `RESPONSE-*` rules (response-body leak
detection) aren't exercised — same inbound-only shape as Next's
middleware limitation.

Peer-deps: `@nestjs/common: ^11`, `@nestjs/core: ^11`. NestJS 10 is
intentionally unsupported — under pnpm it has an `instanceof
HttpException` class-identity bug that breaks the guard's block path.

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

Docs: <https://coraza-incubator.github.io/coraza-node#api-nestjs>
· License: Apache-2.0

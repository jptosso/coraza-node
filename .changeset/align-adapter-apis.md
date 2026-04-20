---
'@coraza/core': minor
'@coraza/next': minor
'@coraza/nestjs': minor
---

Align adapter APIs across the monorepo (pre-1.0 hard changes, no shims).

- `@coraza/next`: the middleware factory is now `coraza({ waf, ...opts })`,
  matching Express and Fastify. The legacy `createCorazaMiddleware(waf, opts)`
  export is gone.
- `@coraza/nestjs`: adds `onBlock?: (interruption) => HttpException` on
  `CorazaNestOptions` so consumers can customize the thrown exception.
- `@coraza/core`: `Transaction.processRequest` and
  `Transaction.processRequestBody` are removed. `processRequestBundle` is
  the only public request-phase entry point — it runs phases 1 + 2
  atomically, which is what closed the 60% attack-miss bug. `Abi`,
  `encodeHeaders`, `ABI_MAJOR`, `instantiate`, and `patchInitialMemory`
  move behind a new `@coraza/core/internal` subpath export. The
  `Interruption` type grows an optional `source: 'waf-error'` tag that
  adapters set on the 503 they synthesize when the WAF itself fails — so
  `onBlock` handlers can distinguish a CRS block from an availability
  failure.

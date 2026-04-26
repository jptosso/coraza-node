// next15-middleware — Next 15 defaults the middleware to the Node runtime
// with webpack. We still pin `runtime: 'nodejs'` on the config export
// because the compatibility matrix is meant to catch regressions that
// happen when users follow the documented quick-start verbatim.

import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/next'

const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)

// No `wasmSource` override on purpose — the matrix's job is to prove
// that the documented quick-start works as published. If the library
// can't resolve its own WASM under Next 15's middleware bundler, that's
// a library bug, not something we hide behind a workaround here.
const wafPromise = usePool
  ? createWAFPool({ rules: recommended(), mode: 'block', size: poolSize })
  : createWAF({ rules: recommended(), mode: 'block' })

export const middleware = coraza({ waf: wafPromise })
export const config = {
  matcher: '/:path*',
  runtime: 'nodejs',
}

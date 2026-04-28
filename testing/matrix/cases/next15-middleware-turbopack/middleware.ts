// next15-middleware-turbopack — same file contents as next15-middleware
// but the start script is `next dev --turbo`, which exercises the
// turbopack bundler. This is where loader regressions surface earliest
// because turbopack rewrites `import.meta.url` differently from webpack.

import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/next'

const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)

// Same three-rule disable as examples/express-app — without these the
// inbound anomaly score crosses the PL1 threshold of 5 on every benign
// body-bearing POST and the matrix can't show the benign/malicious split.
const crsTuning = [
  'SecRuleRemoveById 920420',
  'SecRuleRemoveById 920350',
  'SecRuleRemoveById 922110',
].join('\n')
const rules = recommended({ extra: crsTuning })

// Bare API — no `wasmSource` override. Turbopack rewrites import.meta.url
// differently from webpack and the matrix's job is to confirm the core
// fallback handles both. Hiding behind a workaround would defeat the
// purpose.
const wafPromise = usePool
  ? createWAFPool({ rules, mode: 'block', size: poolSize })
  : createWAF({ rules, mode: 'block' })

export const middleware = coraza({ waf: wafPromise })
export const config = {
  matcher: '/:path*',
  runtime: 'nodejs',
}

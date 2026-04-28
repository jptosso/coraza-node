// next16-proxy-turbopack — identical to next16-proxy but boots under
// `next dev --turbo`. Turbopack's `import.meta.url` rewrite differs from
// webpack's — regressions show up here first.

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

// Bare API — no `wasmSource` override. Turbopack's import.meta.url rewrite
// differs from webpack's and the core fallback must handle both.
const wafPromise = usePool
  ? createWAFPool({ rules, mode: 'block', size: poolSize })
  : createWAF({ rules, mode: 'block' })

export const proxy = coraza({ waf: wafPromise })
export const config = { matcher: '/:path*' }

// next16-proxy — Next 16 renamed `middleware.ts` to `proxy.ts`. With the
// `src/` layout, Next 16 only picks up `src/proxy.ts`; a file at the repo
// root is silently ignored. The matrix keeps us honest about that.
//
// `runtime: 'nodejs'` must NOT appear on the config export — Next 16
// rejects that option on proxy files.

import path from 'node:path'
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

const wasmPath = path.resolve(
  process.cwd(),
  '../../../../packages/core/src/wasm/coraza.wasm',
)

const wafPromise = usePool
  ? createWAFPool({
      rules,
      mode: 'block',
      size: poolSize,
      wasmSource: wasmPath,
    })
  : createWAF({
      rules,
      mode: 'block',
      wasmSource: wasmPath,
    })

export const proxy = coraza({ waf: wafPromise })
export const config = { matcher: '/:path*' }

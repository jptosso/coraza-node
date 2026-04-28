// pm-consumer / next16-proxy — Next 16 proxy.ts hosted in src/. Boots
// against the published @coraza/* tarballs installed by the target
// package manager. wasmSource is intentionally omitted: the loader must
// resolve coraza.wasm by walking node_modules from @coraza/core, which
// is the path real users hit.
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/next'

const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)

const wafPromise = usePool
  ? createWAFPool({ rules: recommended(), mode: 'block', size: poolSize })
  : createWAF({ rules: recommended(), mode: 'block' })

export const proxy = coraza({ waf: wafPromise })
export const config = { matcher: '/:path*' }

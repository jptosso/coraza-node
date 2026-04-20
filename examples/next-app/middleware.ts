import path from 'node:path'
import { createWAF } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/next'

const wafDisabled = process.env.WAF === 'off'

// Next's bundler rewrites `import.meta.url` inside middleware to a
// synthetic protocol, so @coraza/core's default URL-based wasm lookup
// fails. Resolve the shipped wasm to an absolute path from the
// example's own CWD — Playwright's webServer.cwd is examples/next-app,
// and Coraza's WASM lives two levels up at packages/core/dist.
const wasmPath = path.resolve(
  process.cwd(),
  '../../packages/core/dist/wasm/coraza.wasm',
)

const wafPromise = wafDisabled
  ? null
  : createWAF({
      rules: recommended(),
      mode: (process.env.MODE ?? 'block') as 'detect' | 'block',
      wasmSource: wasmPath,
    })

export const middleware = wafPromise
  ? coraza({ waf: wafPromise })
  : async () => undefined as unknown as Response

export const config = {
  matcher: '/:path*',
  runtime: 'nodejs',
}

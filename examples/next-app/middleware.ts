import { createWAF } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/next'

const wafDisabled = process.env.WAF === 'off'

const wafPromise = wafDisabled
  ? null
  : createWAF({
      rules: recommended(),
      mode: (process.env.MODE ?? 'block') as 'detect' | 'block',
    })

export const middleware = wafPromise
  ? coraza({ waf: wafPromise })
  : async () => undefined as unknown as Response

export const config = {
  matcher: '/:path*',
  runtime: 'nodejs',
}

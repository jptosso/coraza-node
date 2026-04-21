// @coraza/next — Next.js middleware adapter.
//
// Next 15 defaults its `middleware.ts` to the Node.js runtime, which is the
// only target we support (Edge Runtime lacks WASI).
//
//   // middleware.ts
//   import { createWAF } from '@coraza/core'
//   import { coraza } from '@coraza/next'
//   import { recommended } from '@coraza/coreruleset'
//
//   const waf = createWAF({ rules: recommended(), mode: 'block' })
//   export const middleware = coraza({ waf })
//   export const config = { matcher: '/:path*', runtime: 'nodejs' }
//
// The adapter signature — `coraza({ waf, ...opts })` — matches
// @coraza/express and @coraza/fastify so the mental model transfers.
//
// Design notes:
//   - Uses `processRequestBundle` so phases 1 and 2 run atomically; CRS's
//     phase-2 anomaly evaluator always fires, including on body-less GETs
//     (see docs/threat-model.md).
//   - Fails closed on any WAF error (default `onWAFError: 'block'`).
//   - Logging: Next has no per-request logger; we use the WAF's.

import type {
  AnyWAF,
  WAFLike,
  Interruption,
  Logger,
  SkipOptions,
} from '@coraza/core'
import { buildSkipPredicate } from '@coraza/core'
import { NextResponse, type NextRequest } from 'next/server'

export interface CorazaNextOptions {
  /**
   * A built WAF or WAFPool. A promise is also accepted so `middleware.ts`
   * modules that can't do top-level await (CJS consumers) can defer
   * construction.
   */
  waf: WAFLike
  onBlock?: (interruption: Interruption, req: NextRequest) => Response
  // No `inspectResponse` on this adapter by design — Next's middleware
  // runs on the request boundary and cannot read the Route Handler's
  // response body. CRS's RESPONSE-* families therefore can't fire on a
  // Next deployment. See README and docs/threat-model.md.

  /** Bypass Coraza for static/media paths. Defaults skip /_next/static, etc. */
  skip?: SkipOptions | false
  /**
   * What to do if the WAF throws mid-request. Default 'block' (fail
   * closed with 503). 'allow' is an opt-in availability-over-security
   * knob; see docs/threat-model.md before flipping it.
   */
  onWAFError?: 'allow' | 'block'
}

/**
 * Build a Next.js middleware. Matches the adapter shape used by the
 * other frameworks (`coraza({ waf, ...options })`) — pass a single
 * object with a `waf` key.
 */
export function coraza(
  options: CorazaNextOptions,
): (req: NextRequest) => Promise<Response> {
  const { waf: wafOrPromise, onBlock = defaultBlock, onWAFError = 'block' } = options
  const shouldSkip = options.skip === false ? () => false : buildSkipPredicate(options.skip)

  let wafRef: AnyWAF | null = null
  const ensureWAF = async (): Promise<AnyWAF> => {
    if (wafRef) return wafRef
    wafRef = await wafOrPromise
    return wafRef
  }

  return async function corazaMiddleware(req: NextRequest): Promise<Response> {
    const url = new URL(req.url)
    if (shouldSkip(url.pathname)) return NextResponse.next()

    const waf = await ensureWAF()
    const log = waf.logger

    let tx
    try {
      tx = await waf.newTransaction()
    } catch (err) {
      log.error('coraza: newTransaction failed', { err: (err as Error).message })
      return onWAFError === 'block'
        ? onBlock(
            { ruleId: 0, action: 'deny', status: 503, data: 'WAF unavailable', source: 'waf-error' },
            req,
          )
        : NextResponse.next()
    }

    try {
      if (await tx.isRuleEngineOff()) return NextResponse.next()

      // Read the body up front (Next streams it); the bundle needs it
      // to guarantee phase 2 runs.
      const body = hasBody(req) ? new Uint8Array(await req.arrayBuffer()) : undefined

      const interrupted = await tx.processRequestBundle(
        {
          method: req.method,
          url: url.pathname + url.search,
          protocol: 'HTTP/1.1',
          headers: headersOf(req.headers),
          remoteAddr: req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? '',
        },
        body,
      )
      if (interrupted) {
        return handleBlock(await tx.interruption(), req, onBlock, log)
      }

      return NextResponse.next()
    } catch (err) {
      log.error('coraza: middleware error', { err: (err as Error).message })
      return onWAFError === 'block'
        ? onBlock(
            { ruleId: 0, action: 'deny', status: 503, data: 'WAF internal error', source: 'waf-error' },
            req,
          )
        : NextResponse.next()
    } finally {
      try {
        await tx.processLogging()
      } finally {
        await tx.close()
      }
    }
  }
}

export function defaultBlock(interruption: Interruption, _req: NextRequest): Response {
  return new Response(
    `Request blocked by Coraza (rule ${interruption.ruleId})\n`,
    {
      status: interruption.status || 403,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    },
  )
}

function handleBlock(
  interruption: Interruption | null,
  req: NextRequest,
  onBlock: NonNullable<CorazaNextOptions['onBlock']>,
  log: Logger,
): Response {
  if (!interruption) return NextResponse.next()
  log.warn('coraza: request blocked', {
    ruleId: interruption.ruleId,
    status: interruption.status,
    action: interruption.action,
  })
  return onBlock(interruption, req)
}

function headersOf(h: Headers): [string, string][] {
  const out: [string, string][] = []
  for (const [k, v] of h.entries()) out.push([k, v])
  return out
}

function hasBody(req: NextRequest): boolean {
  const m = req.method.toUpperCase()
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return false
  const len = req.headers.get('content-length')
  if (len !== null) return Number(len) > 0
  return req.headers.has('content-type')
}

export { NextResponse } from 'next/server'
export type { NextRequest } from 'next/server'

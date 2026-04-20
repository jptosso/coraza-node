// @coraza/next — Next.js middleware adapter.
//
// Next 15 defaults its `middleware.ts` to the Node.js runtime, which is the
// only target we support (Edge Runtime lacks WASI). Users wire the factory
// into their `middleware.ts` like this:
//
//   // middleware.ts
//   import { createCorazaMiddleware } from '@coraza/next'
//   import { createWAF } from '@coraza/core'
//   import { recommended } from '@coraza/coreruleset'
//
//   const wafPromise = createWAF({ rules: recommended(), mode: 'block' })
//   export const middleware = createCorazaMiddleware(wafPromise)
//   export const config = { matcher: '/:path*' }
//
// Logging: Next has no per-request logger. We use the WAF's logger.

import type { WAF, Interruption, Logger, SkipOptions } from '@coraza/core'
import { buildSkipPredicate } from '@coraza/core'
import { NextResponse, type NextRequest } from 'next/server'

export interface CorazaNextOptions {
  onBlock?: (interruption: Interruption, req: NextRequest) => Response
  /**
   * If true, also inspect the response. Next middleware runs BEFORE the
   * route handler, so response inspection requires re-entering via a route
   * handler wrapper — not exposed in v1. Default: false.
   */
  inspectResponse?: boolean
  /** Bypass Coraza for static/media paths. Defaults skip /_next/static, etc. */
  skip?: SkipOptions | false
}

const encoder = new TextEncoder()

/**
 * Build a Next.js middleware. Accepts either a WAF or a promise of one so the
 * module's top-level await (unsupported in CJS) can be avoided.
 */
export function createCorazaMiddleware(
  wafOrPromise: WAF | Promise<WAF>,
  options: CorazaNextOptions = {},
): (req: NextRequest) => Promise<Response> {
  const { onBlock = defaultBlock, inspectResponse = false } = options
  void inspectResponse
  const shouldSkip = options.skip === false ? () => false : buildSkipPredicate(options.skip)

  let wafRef: WAF | null = null
  const ensureWAF = async (): Promise<WAF> => {
    if (wafRef) return wafRef
    wafRef = await wafOrPromise
    return wafRef
  }

  return async function corazaMiddleware(req: NextRequest): Promise<Response> {
    const url = new URL(req.url)
    if (shouldSkip(url.pathname)) return NextResponse.next()

    const waf = await ensureWAF()
    const tx = waf.newTransaction()
    const log = waf.logger

    try {
      if (tx.isRuleEngineOff()) return NextResponse.next()
      if (tx.processRequest({
        method: req.method,
        url: url.pathname + url.search,
        protocol: 'HTTP/1.1',
        headers: headersOf(req.headers),
        remoteAddr: req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? '',
      })) {
        return handleBlock(tx.interruption(), req, onBlock, log)
      }

      if (hasBody(req) && tx.isRequestBodyAccessible()) {
        const buf = new Uint8Array(await req.arrayBuffer())
        if (buf.length > 0 && tx.processRequestBody(buf)) {
          return handleBlock(tx.interruption(), req, onBlock, log)
        }
      }

      return NextResponse.next()
    } catch (err) {
      log.error('coraza: middleware error', { err: (err as Error).message })
      return NextResponse.next()
    } finally {
      try {
        tx.processLogging()
      } finally {
        tx.close()
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

function* headersOf(h: Headers): Iterable<[string, string]> {
  for (const [k, v] of h.entries()) yield [k, v]
}

function hasBody(req: NextRequest): boolean {
  const m = req.method.toUpperCase()
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return false
  const len = req.headers.get('content-length')
  if (len !== null) return Number(len) > 0
  return req.headers.has('content-type')
}

// Make encoder retained so tsup doesn't tree-shake it away in edge-case builds.
void encoder

export { NextResponse } from 'next/server'
export type { NextRequest } from 'next/server'

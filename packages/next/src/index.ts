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
  SkipOptions,
  IgnoreSpec,
  IgnoreContext,
  IgnoreVerdict,
} from '@coraza/core'
import { buildIgnoreMatcher, skipToIgnore } from '@coraza/core'
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

  /** Unified WAF-bypass spec. See README "Skipping the WAF". */
  ignore?: IgnoreSpec | false
  /**
   * @deprecated Use `ignore:` instead. Mapped at construction with a
   * one-shot deprecation warning. Removed at stable 0.1.
   */
  skip?: SkipOptions | false
  /**
   * What to do if the WAF throws mid-request. Default 'block' (fail
   * closed with 503). 'allow' is an opt-in availability-over-security
   * knob; see docs/threat-model.md before flipping it.
   */
  onWAFError?: 'allow' | 'block'
  /**
   * Whether to read the request body and feed it to Coraza. Default `true`.
   *
   * When `false`, the runner skips `req.arrayBuffer()` entirely — the
   * body is left untouched on the way to your route handler, and CRS's
   * body-targeted rules (SQLi/XSS/RCE that match `ARGS_POST`/`REQUEST_BODY`)
   * cannot fire. URL/header/cookie rules still evaluate normally, and
   * the bundle still triggers phase 2 (anomaly score, etc.) on
   * non-body inputs.
   *
   * Why you might flip it off:
   *   - You're on a Next runtime that doesn't re-inject the body
   *     reliably to the route handler after the proxy reads it.
   *   - Body inspection is your dominant source of CRS false positives
   *     and you'd rather defend with header/URL rules only.
   *   - You're streaming large uploads that you don't want buffered
   *     into Coraza memory.
   *
   * Security trade-off: significant. Body-targeted attacks (most XSS,
   * many SQLi) won't be detected. Document why you flipped it.
   *
   * @default true
   */
  inspectBody?: boolean
}

/**
 * Outcome returned by {@link createCorazaRunner}.
 *
 * - `{ blocked: Response }` — Coraza (or the configured `onWAFError`
 *   policy) has produced a terminal response; the caller must return it
 *   unchanged. Do NOT compose further proxy logic on top — returning a
 *   "soft" response after a block defeats the WAF.
 * - `{ allow: true }` — the request passed Coraza. The caller is free to
 *   run its own `proxy.ts` logic (auth, redirects, header rewrites, etc.)
 *   and then `NextResponse.next()` (or whatever it normally returns).
 */
export type CorazaDecision = { blocked: Response } | { allow: true }

/**
 * Build a runner that evaluates a request through Coraza and returns a
 * structured decision — intended for projects that already have a
 * `proxy.ts` and want to compose Coraza with their existing logic
 * (auth, redirects, etc.) without sniffing `x-middleware-next` headers.
 *
 * ```ts
 * // proxy.ts
 * import { createCorazaRunner } from '@coraza/next'
 * const runCoraza = createCorazaRunner({ waf })
 *
 * export async function proxy(req: NextRequest) {
 *   const decision = await runCoraza(req)
 *   if ('blocked' in decision) return decision.blocked
 *   // ...existing auth / redirect logic
 *   return NextResponse.next()
 * }
 * ```
 *
 * The decision contract is stable public API; the `x-middleware-next`
 * trick used previously is not.
 */
export function createCorazaRunner(
  options: CorazaNextOptions,
): (req: NextRequest) => Promise<CorazaDecision> {
  const {
    waf: wafOrPromise,
    onBlock = defaultBlock,
    onWAFError = 'block',
    inspectBody = true,
  } = options
  const matcher = resolveIgnoreMatcher(options.ignore, options.skip)

  let wafRef: AnyWAF | null = null
  const ensureWAF = async (): Promise<AnyWAF> => {
    if (wafRef) return wafRef
    wafRef = await wafOrPromise
    return wafRef
  }

  return async function runCoraza(req: NextRequest): Promise<CorazaDecision> {
    const url = new URL(req.url)
    const verdict = matcher === null ? false : matcher(buildIgnoreCtx(req, url))
    if (verdict === true) return { allow: true }

    const waf = await ensureWAF()
    const log = waf.logger

    let tx
    try {
      tx = await waf.newTransaction()
    } catch (err) {
      log.error('coraza: newTransaction failed', { err: (err as Error).message })
      if (onWAFError === 'block') {
        return {
          blocked: onBlock(
            { ruleId: 0, action: 'deny', status: 503, data: 'WAF unavailable', source: 'waf-error' },
            req,
          ),
        }
      }
      return { allow: true }
    }

    try {
      if (await tx.isRuleEngineOff()) return { allow: true }

      // to guarantee phase 2 runs. Skip the read when:
      //   - the ignore: spec said `'skip-body'` (large-upload bypass), OR
      //   - the consumer set `inspectBody: false` (body-targeted rules
      //     disabled by config).
      const body =
        verdict === 'skip-body' || !inspectBody
          ? undefined
          : hasBody(req)
            ? new Uint8Array(await req.arrayBuffer())
            : undefined

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
        const interruption = await tx.interruption()
        if (!interruption) return { allow: true }
        log.warn('coraza: request blocked', {
          ruleId: interruption.ruleId,
          status: interruption.status,
          action: interruption.action,
        })
        return { blocked: onBlock(interruption, req) }
      }

      return { allow: true }
    } catch (err) {
      log.error('coraza: middleware error', { err: (err as Error).message })
      if (onWAFError === 'block') {
        return {
          blocked: onBlock(
            { ruleId: 0, action: 'deny', status: 503, data: 'WAF internal error', source: 'waf-error' },
            req,
          ),
        }
      }
      return { allow: true }
    } finally {
      try {
        await tx.processLogging()
      } finally {
        await tx.close()
      }
    }
  }
}

/**
 * Build a Next.js middleware. Matches the adapter shape used by the
 * other frameworks (`coraza({ waf, ...options })`) — pass a single
 * object with a `waf` key.
 *
 * Thin wrapper around {@link createCorazaRunner} that returns a
 * `NextResponse.next()` on allow. If you need to compose with existing
 * proxy logic (auth, redirects, etc.), use `createCorazaRunner` directly
 * so the decision stays structured and you don't have to sniff
 * `x-middleware-next` on the response.
 */
export function coraza(
  options: CorazaNextOptions,
): (req: NextRequest) => Promise<Response> {
  const run = createCorazaRunner(options)
  return async function corazaMiddleware(req: NextRequest): Promise<Response> {
    const decision = await run(req)
    if ('blocked' in decision) return decision.blocked
    return NextResponse.next()
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

let legacyWarnedNext = false

function resolveIgnoreMatcher(
  ignore: IgnoreSpec | false | undefined,
  skip: SkipOptions | false | undefined,
): ((ctx: IgnoreContext) => IgnoreVerdict) | null {
  if (ignore === false || skip === false) return null
  if (ignore !== undefined) return buildIgnoreMatcher(ignore)
  if (skip !== undefined && !legacyWarnedNext) {
    legacyWarnedNext = true
    // eslint-disable-next-line no-console
    console.warn(
      'coraza: the `skip:` option is deprecated and will be removed at stable 0.1; ' +
        'migrate to `ignore: { extensions, routes, methods, bodyLargerThan, headerEquals, match }`.',
    )
  }
  return buildIgnoreMatcher(skipToIgnore(skip))
}

function buildIgnoreCtx(req: NextRequest, url: URL): IgnoreContext {
  const cl = req.headers.get('content-length')
  const clNum = cl !== null ? Number(cl) : NaN
  return Object.freeze({
    method: req.method,
    url,
    headers: req.headers,
    contentLength: Number.isFinite(clNum) && clNum >= 0 ? clNum : null,
  })
}

export { NextResponse } from 'next/server'
export type { NextRequest } from 'next/server'

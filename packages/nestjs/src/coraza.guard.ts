/**
 * CorazaGuard — a Nest `CanActivate` that runs every request through a WAF
 * (or `WAFPool`) via the shared `processRequestBundle` atomic call.
 *
 * Blocks become `HttpException` (override with `onBlock` in `CorazaModule`).
 * Fails closed on internal WAF errors unless `onWAFError: 'allow'`.
 * Respects the usual `skip` static-asset bypass and `isRuleEngineOff()`.
 */
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  HttpException,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common'
import type {
  AnyWAF,
  Transaction,
  WorkerTransaction,
  Interruption,
  MatchedRule,
  SkipOptions,
  IgnoreSpec,
  IgnoreContext,
  IgnoreVerdict,
} from '@coraza/core'
import { buildIgnoreMatcher, skipToIgnore } from '@coraza/core'
import { CORAZA_WAF, CORAZA_OPTIONS } from './tokens.js'

/**
 * Optional context passed as the second argument to a custom `onBlock`.
 * Only populated when `verboseLog: true`; lets the consumer log every
 * contributing CRS rule (the `Interruption` only carries the terminating
 * rule, which for CRS is almost always 949110 / inbound anomaly score).
 */
export interface CorazaBlockContext {
  matchedRules: MatchedRule[]
}

type OnBlock = (interruption: Interruption, ctx?: CorazaBlockContext) => HttpException

/**
 * Default `onBlock` for `CorazaModule.forRoot`: a 403-ish HttpException
 * carrying the matched rule id. Exported so consumers who want to wrap
 * the default can delegate to it:
 *
 *   CorazaModule.forRoot({
 *     waf,
 *     onBlock: (i) => {
 *       metrics.increment('waf.block', { rule: i.ruleId })
 *       return defaultHttpException(i)
 *     },
 *   })
 *
 * Mirrors `defaultBlock` from `@coraza/express` / `@coraza/fastify` /
 * `@coraza/next` for API symmetry across the four adapters.
 */
export const defaultHttpException: OnBlock = (i) =>
  new HttpException(`Request blocked by Coraza (rule ${i.ruleId})`, i.status || 403)

const defaultOnBlock = defaultHttpException

// Minimal shapes of Express/Fastify request+reply that NestJS exposes via
// switchToHttp(). We avoid a hard dep on either framework.
interface HttpReq {
  method: string
  url?: string
  originalUrl?: string
  httpVersion?: string
  headers: Record<string, string | string[] | undefined>
  /**
   * Node IncomingMessage.rawHeaders — flat [name, value, name, value, …]
   * preserving original casing and multi-value pairs. We prefer this
   * over `headers` because Node folds list-form headers (X-Forwarded-For
   * etc.) into a comma-joined string at the IncomingMessage layer,
   * losing per-hop boundaries.
   */
  rawHeaders?: string[]
  body?: unknown
  ip?: string
  socket?: { remotePort?: number; localPort?: number }
  raw?: { httpVersion?: string; rawHeaders?: string[] }
}

const encoder = new TextEncoder()
type AnyTx = Transaction | WorkerTransaction

@Injectable()
export class CorazaGuard implements CanActivate {
  private readonly logger = new Logger('CorazaGuard')
  private readonly matcher: ((ctx: IgnoreContext) => IgnoreVerdict) | null
  private readonly onWAFError: 'allow' | 'block'
  private readonly onBlock: OnBlock
  private readonly verboseLog: boolean

  constructor(
    @Inject(CORAZA_WAF) private readonly waf: AnyWAF,
    @Inject(CORAZA_OPTIONS)
    opts: {
      ignore?: IgnoreSpec | false
      skip?: SkipOptions | false
      onWAFError?: 'allow' | 'block'
      onBlock?: OnBlock
      verboseLog?: boolean
    } = {},
  ) {
    this.matcher = resolveIgnoreMatcher(opts.ignore, opts.skip)
    this.onWAFError = opts.onWAFError ?? 'block'
    this.onBlock = opts.onBlock ?? defaultOnBlock
    this.verboseLog = opts.verboseLog ?? false
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const http = ctx.switchToHttp()
    const req = http.getRequest<HttpReq>()

    const verdict = this.matcher === null ? false : this.matcher(buildIgnoreCtx(req))
    if (verdict === true) return true

    let tx: AnyTx
    try {
      tx = await this.waf.newTransaction()
    } catch (err) {
      this.logger.error(`newTransaction failed: ${(err as Error).message}`)
      if (this.onWAFError === 'block') {
        throw this.onBlock({
          ruleId: 0,
          action: 'deny',
          status: 503,
          data: 'WAF unavailable',
          source: 'waf-error',
        })
      }
      return true
    }
    ;(req as HttpReq & { _corazaTx?: AnyTx })._corazaTx = tx

    let interruption: Interruption | null = null
    let matched: MatchedRule[] | undefined
    try {
      if (await tx.isRuleEngineOff()) return true

      // Phases 1 and 2 run atomically via the fused bundle call so CRS's
      // anomaly evaluator at phase 2 always fires, including on body-less
      // GET requests. See docs/threat-model.md.
      const body = verdict === 'skip-body' ? undefined : serializeBody(req.body)
      const interrupted = await tx.processRequestBundle(
        {
          method: req.method,
          url: req.originalUrl || req.url || '/',
          protocol: `HTTP/${req.httpVersion ?? req.raw?.httpVersion ?? '1.1'}`,
          headers: headersOf(req.headers, req.rawHeaders ?? req.raw?.rawHeaders),
          remoteAddr: req.ip ?? '',
          remotePort: req.socket?.remotePort ?? 0,
          serverPort: req.socket?.localPort ?? 0,
        },
        body,
      )
      if (interrupted) {
        interruption = await tx.interruption()
        // Pull matched rules BEFORE the finally block closes the tx.
        if (interruption && this.verboseLog) {
          try {
            matched = await tx.matchedRules()
          } catch {
            matched = undefined
          }
        }
      }
    } catch (err) {
      this.logger.error(`middleware error: ${(err as Error).message}`)
      if (this.onWAFError === 'block') {
        try {
          await tx.processLogging()
        } finally {
          await tx.close()
        }
        throw this.onBlock({
          ruleId: 0,
          action: 'deny',
          status: 503,
          data: 'WAF internal error',
          source: 'waf-error',
        })
      }
      // onWAFError === 'allow' falls through to processLogging + close
      // + return true below.
    } finally {
      try {
        await tx.processLogging()
      } finally {
        await tx.close()
      }
    }

    if (interruption) {
      const dataSuffix = interruption.data ? ` data="${interruption.data}"` : ''
      this.logger.warn(
        `blocked request (rule=${interruption.ruleId} action=${interruption.action} status=${interruption.status})${dataSuffix}`,
      )
      if (matched) {
        for (const r of matched) {
          this.logger.warn(
            `coraza: matched (rule=${r.id} severity=${r.severity}) ${r.message}`,
          )
        }
      }
      throw matched
        ? this.onBlock(interruption, { matchedRules: matched })
        : this.onBlock(interruption)
    }
    return true
  }
}

function headersOf(
  h: Record<string, string | string[] | undefined>,
  rawHeaders?: string[],
): [string, string][] {
  // Prefer `req.rawHeaders` (Express) / `req.raw.rawHeaders` (Fastify)
  // when available — it preserves multi-value headers as distinct
  // entries, where `req.headers` would join them into a single
  // comma-separated string and lose the per-hop boundary.
  if (Array.isArray(rawHeaders) && rawHeaders.length >= 2) {
    const out: [string, string][] = []
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
      out.push([rawHeaders[i]!.toLowerCase(), rawHeaders[i + 1]!])
    }
    return out
  }
  const out: [string, string][] = []
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const item of v) out.push([k, item])
    } else {
      out.push([k, v])
    }
  }
  return out
}

function serializeBody(body: unknown): Uint8Array | undefined {
  if (body === undefined || body === null) return undefined
  if (body instanceof Uint8Array) return body
  if (typeof body === 'string') return encoder.encode(body)
  if (typeof body === 'object') {
    if (Object.keys(body as object).length === 0) return undefined
    try {
      return encoder.encode(JSON.stringify(body))
    } catch {
      return undefined
    }
  }
  return undefined
}

let legacyWarnedNest = false

function resolveIgnoreMatcher(
  ignore: IgnoreSpec | false | undefined,
  skip: SkipOptions | false | undefined,
): ((ctx: IgnoreContext) => IgnoreVerdict) | null {
  if (ignore === false || skip === false) return null
  if (ignore !== undefined) return buildIgnoreMatcher(ignore)
  if (skip !== undefined && !legacyWarnedNest) {
    legacyWarnedNest = true
    // eslint-disable-next-line no-console
    console.warn(
      'coraza: the `skip:` option is deprecated and will be removed at stable 0.1; ' +
        'migrate to `ignore: { extensions, routes, methods, bodyLargerThan, headerEquals, match }`.',
    )
  }
  return buildIgnoreMatcher(skipToIgnore(skip))
}

function buildIgnoreCtx(req: HttpReq): IgnoreContext {
  const raw = req.originalUrl || req.url || '/'
  let url: URL
  try {
    url = new URL(raw, 'http://x')
  } catch {
    /* c8 ignore next */
    url = new URL('/', 'http://x')
  }
  const map = new Map<string, string>()
  for (const k in req.headers) {
    const v = req.headers[k]
    if (v === undefined) continue
    map.set(k, Array.isArray(v) ? v.join(',') : v)
  }
  const cl = req.headers['content-length']
  const clNum = typeof cl === 'string' ? Number(cl) : Array.isArray(cl) ? Number(cl[0]) : NaN
  return Object.freeze({
    method: req.method,
    url,
    headers: map,
    contentLength: Number.isFinite(clNum) && clNum >= 0 ? clNum : null,
  })
}

export { ForbiddenException }

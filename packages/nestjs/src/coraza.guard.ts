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
  SkipOptions,
} from '@coraza/core'
import { buildSkipPredicate, pathOf } from '@coraza/core'
import { CORAZA_WAF, CORAZA_OPTIONS } from './tokens.js'

type OnBlock = (interruption: Interruption) => HttpException

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
  body?: unknown
  ip?: string
  socket?: { remotePort?: number; localPort?: number }
  raw?: { httpVersion?: string }
}

const encoder = new TextEncoder()
type AnyTx = Transaction | WorkerTransaction

@Injectable()
export class CorazaGuard implements CanActivate {
  private readonly logger = new Logger('CorazaGuard')
  private readonly shouldSkip: (path: string) => boolean
  private readonly onWAFError: 'allow' | 'block'
  private readonly onBlock: OnBlock

  constructor(
    @Inject(CORAZA_WAF) private readonly waf: AnyWAF,
    @Inject(CORAZA_OPTIONS)
    opts: {
      skip?: SkipOptions | false
      onWAFError?: 'allow' | 'block'
      onBlock?: OnBlock
    } = {},
  ) {
    this.shouldSkip = opts.skip === false ? () => false : buildSkipPredicate(opts.skip)
    this.onWAFError = opts.onWAFError ?? 'block'
    this.onBlock = opts.onBlock ?? defaultOnBlock
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const http = ctx.switchToHttp()
    const req = http.getRequest<HttpReq>()

    if (this.shouldSkip(pathOf(req.originalUrl || req.url || '/'))) return true

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
    try {
      if (await tx.isRuleEngineOff()) return true

      // Phases 1 and 2 run atomically via the fused bundle call so CRS's
      // anomaly evaluator at phase 2 always fires, including on body-less
      // GET requests. See docs/threat-model.md.
      const interrupted = await tx.processRequestBundle(
        {
          method: req.method,
          url: req.originalUrl || req.url || '/',
          protocol: `HTTP/${req.httpVersion ?? req.raw?.httpVersion ?? '1.1'}`,
          headers: headersOf(req.headers),
          remoteAddr: req.ip ?? '',
          remotePort: req.socket?.remotePort ?? 0,
          serverPort: req.socket?.localPort ?? 0,
        },
        serializeBody(req.body),
      )
      if (interrupted) interruption = await tx.interruption()
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
      this.logger.warn(
        `blocked request (rule=${interruption.ruleId} action=${interruption.action} status=${interruption.status})`,
      )
      throw this.onBlock(interruption)
    }
    return true
  }
}

function headersOf(
  h: Record<string, string | string[] | undefined>,
): [string, string][] {
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

export { ForbiddenException }

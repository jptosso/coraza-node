import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  HttpException,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common'
import type { WAF, Interruption, Transaction, SkipOptions } from '@coraza/core'
import { buildSkipPredicate, pathOf } from '@coraza/core'
import { CORAZA_WAF, CORAZA_OPTIONS } from './tokens.js'

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
interface HttpRes {
  headersSent?: boolean
  sent?: boolean
  statusCode?: number
  setHeader?(k: string, v: string): void
  end?(body?: string): void
}

const encoder = new TextEncoder()

@Injectable()
export class CorazaGuard implements CanActivate {
  private readonly logger = new Logger('CorazaGuard')
  private readonly shouldSkip: (path: string) => boolean

  constructor(
    @Inject(CORAZA_WAF) private readonly waf: WAF,
    @Inject(CORAZA_OPTIONS) opts: { skip?: SkipOptions | false } = {},
  ) {
    this.shouldSkip = opts.skip === false ? () => false : buildSkipPredicate(opts.skip)
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const http = ctx.switchToHttp()
    const req = http.getRequest<HttpReq>()
    const res = http.getResponse<HttpRes>()

    if (this.shouldSkip(pathOf(req.originalUrl || req.url || '/'))) return true

    const tx = this.waf.newTransaction()

    // Record tx on the request so an interceptor could inspect later.
    ;(req as HttpReq & { _corazaTx?: Transaction })._corazaTx = tx

    let interruption: Interruption | null = null
    if (tx.isRuleEngineOff()) {
      tx.processLogging()
      tx.close()
      return true
    }
    try {
      if (
        tx.processRequest({
          method: req.method,
          url: req.originalUrl || req.url || '/',
          protocol: `HTTP/${req.httpVersion ?? req.raw?.httpVersion ?? '1.1'}`,
          headers: headersOf(req.headers),
          remoteAddr: req.ip ?? '',
          remotePort: req.socket?.remotePort ?? 0,
          serverPort: req.socket?.localPort ?? 0,
        })
      ) {
        interruption = tx.interruption()
      } else if (tx.isRequestBodyAccessible()) {
        const body = serializeBody(req.body)
        if (body && tx.processRequestBody(body)) {
          interruption = tx.interruption()
        }
      }
    } catch (err) {
      this.logger.error(`middleware error: ${(err as Error).message}`)
    } finally {
      // NestJS guards run before the handler. We emit audit logs + close the
      // transaction immediately (interceptor-driven response inspection is
      // out of v1 scope).
      tx.processLogging()
      tx.close()
    }

    if (interruption) {
      this.logger.warn(
        `blocked request (rule=${interruption.ruleId} action=${interruption.action} status=${interruption.status})`,
      )
      throw new HttpException(
        `Request blocked by Coraza (rule ${interruption.ruleId})`,
        interruption.status || 403,
      )
    }
    return true
  }
}

function* headersOf(
  h: Record<string, string | string[] | undefined>,
): Iterable<[string, string]> {
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const item of v) yield [k, item]
    } else {
      yield [k, v]
    }
  }
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

// Re-exported for callers who want to throw the same shape manually.
export { ForbiddenException }

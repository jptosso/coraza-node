// @coraza/express — Express middleware wrapping @coraza/core.
//
// Usage:
//
//   import { coraza } from '@coraza/express'
//   import { createWAF } from '@coraza/core'
//   import { recommended } from '@coraza/coreruleset'
//
//   const waf = await createWAF({ rules: recommended(), mode: 'block' })
//   app.use(coraza({ waf }))
//
// Logging: Express has no built-in logger. If the request carries `req.log`
// (pino-http convention) we prefer it; otherwise we use the WAF's logger.

import type { WAF, Interruption, Logger, Transaction, SkipOptions } from '@coraza/core'
import { buildSkipPredicate, pathOf } from '@coraza/core'
import type { Request, RequestHandler, Response } from 'express'

export interface CorazaExpressOptions {
  /** The WAF created via @coraza/core's createWAF. */
  waf: WAF
  /**
   * Override how a block decision is turned into an HTTP response.
   * Default: sets status + plain-text body with the interruption's rule id.
   */
  onBlock?: (interruption: Interruption, req: Request, res: Response) => void
  /**
   * Inspect the response phase (headers + body) in addition to the request.
   * Default: `false`. Response inspection doubles per-request work; enable
   * only if you have response-side rules (e.g. data-leak detection).
   */
  inspectResponse?: boolean
  /**
   * Bypass Coraza for matching requests. Defaults match common static-asset
   * paths and extensions (images, CSS, JS, fonts, /_next/static, /public/…).
   * Pass `{ skipDefaults: true }` to disable the defaults entirely.
   * Pass `false` to disable bypass altogether.
   */
  skip?: SkipOptions | false
}

type ReqWithLog = Request & { log?: Logger }

const encoder = new TextEncoder()

export function coraza(options: CorazaExpressOptions): RequestHandler {
  const { waf, onBlock = defaultBlock, inspectResponse = false } = options
  const shouldSkip = options.skip === false ? () => false : buildSkipPredicate(options.skip)

  return function corazaMiddleware(req, res, next) {
    if (shouldSkip(pathOf(req.originalUrl || req.url))) {
      next()
      return
    }
    const log = pickLogger(req as ReqWithLog, waf.logger)
    let tx
    try {
      tx = waf.newTransaction()
    } catch (err) {
      log.error('coraza: newTransaction failed', { err: (err as Error).message })
      next()
      return
    }

    res.once('close', () => {
      try {
        tx.processLogging()
      } finally {
        tx.close()
      }
    })

    // Cheapest possible skip — SecRuleEngine Off means we don't do any work.
    if (tx.isRuleEngineOff()) {
      next()
      return
    }

    try {
      const requestInterrupt = tx.processRequest({
        method: req.method,
        url: req.originalUrl || req.url,
        protocol: `HTTP/${req.httpVersion}`,
        headers: headersOf(req.headers),
        remoteAddr: req.ip ?? '',
        remotePort: req.socket.remotePort ?? 0,
        serverPort: req.socket.localPort ?? 0,
      })
      if (requestInterrupt) {
        return emitBlock(tx.interruption(), req, res, onBlock, log)
      }

      if (tx.isRequestBodyAccessible()) {
        const bodyBuf = extractBody(req)
        if (bodyBuf && tx.processRequestBody(bodyBuf)) {
          return emitBlock(tx.interruption(), req, res, onBlock, log)
        }
      }

      if (inspectResponse) {
        hookResponse(tx, res, (it) => emitBlock(it, req, res, onBlock, log), log)
      }

      next()
    } catch (err) {
      log.error('coraza: middleware error', { err: (err as Error).message })
      next()
    }
  }
}

export function defaultBlock(interruption: Interruption, _req: Request, res: Response): void {
  if (res.headersSent) return
  res
    .status(interruption.status || 403)
    .type('text/plain')
    .send(`Request blocked by Coraza (rule ${interruption.ruleId})\n`)
}

function emitBlock(
  interruption: Interruption | null,
  req: Request,
  res: Response,
  onBlock: NonNullable<CorazaExpressOptions['onBlock']>,
  log: Logger,
): void {
  /* c8 ignore next — defensive: tx_has_interrupt=1 but get_interrupt=null is a bug */
  if (!interruption) return
  log.warn('coraza: request blocked', {
    ruleId: interruption.ruleId,
    status: interruption.status,
    action: interruption.action,
  })
  onBlock(interruption, req, res)
}

function* headersOf(
  h: Record<string, string | string[] | undefined>,
): Iterable<[string, string]> {
  for (const k in h) {
    const v = h[k]
    if (Array.isArray(v)) {
      for (const item of v) yield [k, item]
    } else if (v !== undefined) {
      yield [k, v]
    }
  }
}

function extractBody(req: Request): Uint8Array | undefined {
  const b = (req as Request & { body?: unknown }).body
  if (b === undefined || b === null) return undefined
  if (b instanceof Uint8Array) return b
  if (typeof b === 'string') return encoder.encode(b)
  if (typeof b !== 'object') return undefined
  if (Object.keys(b as object).length === 0) return undefined
  try {
    return encoder.encode(JSON.stringify(b))
  } catch {
    return undefined
  }
}

function hookResponse(
  tx: Transaction,
  res: Response,
  onInterrupt: (it: Interruption) => void,
  log: Logger,
): void {
  const origWriteHead = res.writeHead.bind(res)
  let headersDone = false
  res.writeHead = ((...args: unknown[]) => {
    if (!headersDone) {
      headersDone = true
      try {
        if (
          tx.processResponse({
            status: args[0] as number,
            headers: headersFromNodeRes(res),
            protocol: 'HTTP/1.1',
          })
        ) {
          const it = tx.interruption()
          if (it) onInterrupt(it)
        }
      } catch (err) {
        log.error('coraza: response-header inspection failed', { err: (err as Error).message })
      }
    }
    return (origWriteHead as (...a: unknown[]) => Response).apply(res, args)
  }) as typeof res.writeHead

  const origEnd = res.end.bind(res)
  res.end = ((...args: unknown[]) => {
    const chunk = args[0]
    if (chunk != null && tx.isResponseBodyProcessable()) {
      try {
        const buf = chunk instanceof Uint8Array ? chunk : encoder.encode(String(chunk))
        if (tx.processResponseBody(buf)) {
          const it = tx.interruption()
          /* c8 ignore next */
          if (it) onInterrupt(it)
        }
      } catch (err) {
        log.error('coraza: response-body inspection failed', { err: (err as Error).message })
      }
    }
    return (origEnd as (...a: unknown[]) => Response).apply(res, args)
  }) as typeof res.end
}

function headersFromNodeRes(res: Response): Iterable<[string, string]> {
  const out: [string, string][] = []
  for (const name of res.getHeaderNames()) {
    const v = res.getHeader(name)!
    if (Array.isArray(v)) {
      for (const item of v) out.push([name, String(item)])
    } else {
      out.push([name, String(v)])
    }
  }
  return out
}

function pickLogger(req: ReqWithLog, fallback: Logger): Logger {
  // If the request carries a logger (pino-http convention) use it wholesale;
  // otherwise fall back to the WAF's logger.
  return (req.log as Logger | undefined) ?? fallback
}

export type { Request, Response, NextFunction } from 'express'

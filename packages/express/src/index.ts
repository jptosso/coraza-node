// @coraza/express — Express middleware wrapping @coraza/core.
//
// Usage (single WAF, simplest):
//
//   import { coraza } from '@coraza/express'
//   import { createWAF } from '@coraza/core'
//   const waf = await createWAF({ rules, mode: 'block' })
//   app.use(coraza({ waf }))
//
// Usage (WAFPool, multi-core scaling):
//
//   import { createWAFPool } from '@coraza/core'
//   const pool = await createWAFPool({ rules, size: os.availableParallelism() })
//   app.use(coraza({ waf: pool }))
//
// Logging: Express has no built-in logger. If the request carries `req.log`
// (pino-http convention) we prefer it; otherwise we use the WAF's logger.

import type {
  WAF,
  WAFPool,
  Transaction,
  Interruption,
  Logger,
  SkipOptions,
} from '@coraza/core'
import { buildSkipPredicate, pathOf } from '@coraza/core'
import type { Request, RequestHandler, Response } from 'express'

export interface CorazaExpressOptions {
  /**
   * A `WAF` (single instance, sync) or a `WAFPool` (worker_threads, async).
   * Pools scale linearly up to CPU count with a small latency overhead —
   * prefer them under production load. See @coraza/core for construction.
   */
  waf: WAF | WAFPool
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

  // `waf` is either a sync WAF or an async WAFPool. Both expose the same
  // surface (newTransaction / Transaction has the same method names). We
  // `await` every call so the middleware works against either.
  return async function corazaMiddleware(req, res, next) {
    if (shouldSkip(pathOf(req.originalUrl || req.url))) {
      next()
      return
    }
    const log = pickLogger(req as ReqWithLog, waf.logger)

    let tx: AnyTransaction
    try {
      tx = await waf.newTransaction()
    } catch (err) {
      log.error('coraza: newTransaction failed', { err: (err as Error).message })
      next()
      return
    }

    res.once('close', () => {
      // Fire-and-forget — don't block response teardown.
      void Promise.resolve(tx.processLogging())
        .catch(() => {})
        .finally(() => tx.close())
    })

    try {
      if (await tx.isRuleEngineOff()) {
        next()
        return
      }

      // Fused path: pack connection+URI+headers+body into one WASM call.
      // Express's body-parser middleware has already buffered req.body by
      // the time we run, so we have everything we need. This saves 4-8
      // MessagePort round-trips under WAFPool.
      const reqInfo: RequestInfo = {
        method: req.method,
        url: req.originalUrl || req.url,
        protocol: `HTTP/${req.httpVersion}`,
        headers: headersOf(req.headers),
        remoteAddr: req.ip ?? '',
        remotePort: req.socket.remotePort ?? 0,
        serverPort: req.socket.localPort ?? 0,
      }
      const bodyBuf = extractBody(req)
      const interrupted = await tx.processRequestBundle(reqInfo, bodyBuf)
      if (interrupted) {
        return emitBlock(await tx.interruption(), req, res, onBlock, log)
      }

      if (inspectResponse) {
        // Response hooks patch res.writeHead / res.end synchronously. They
        // only work with the sync `WAF` path — a pool's async methods can't
        // block mid-write. Skip quietly under pools; log once so users know.
        if (isSyncTx(tx)) {
          hookResponse(tx, res, (it) => emitBlock(it, req, res, onBlock, log), log)
        } else {
          log.warn(
            'coraza: inspectResponse=true is a no-op when using WAFPool; use a single WAF or drop response inspection',
          )
        }
      }

      next()
    } catch (err) {
      log.error('coraza: middleware error', { err: (err as Error).message })
      next()
    }
  }
}

// A union of Transaction (sync) and WorkerTransaction (async) — both have
// the same method names; differing return types get uniformly awaited.
type AnyTransaction = Awaited<ReturnType<(WAF | WAFPool)['newTransaction']>>


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

function headersOf(
  h: Record<string, string | string[] | undefined>,
): [string, string][] {
  // Must return a concrete array (not a generator) so the WAFPool path can
  // structured-clone it across the MessagePort.
  const out: [string, string][] = []
  for (const k in h) {
    const v = h[k]
    if (Array.isArray(v)) {
      for (const item of v) out.push([k, item])
    } else if (v !== undefined) {
      out.push([k, v])
    }
  }
  return out
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

// A Transaction (sync) vs a WorkerTransaction (async) can be distinguished
// by checking whether processRequest returned a Promise. Instead of that
// (requires running a call), we use a structural check: sync txs have
// non-async method signatures but at runtime they share. We tag via a
// symbol during newTransaction — simpler: peek the return type of
// `isRuleEngineOff()` by calling it and checking for a Promise. Cheapest:
// just check if `close` returns a Promise.
function isSyncTx(tx: AnyTransaction): tx is Transaction {
  // WorkerTransaction methods are defined with `async`; their prototype's
  // constructor is 'AsyncFunction'. Transaction methods are plain.
  return (tx.close as { constructor: { name: string } }).constructor.name !== 'AsyncFunction'
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

function headersFromNodeRes(res: Response): [string, string][] {
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

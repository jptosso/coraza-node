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
  AnyWAF,
  WAFLike,
  Transaction,
  Interruption,
  Logger,
  MatchedRule,
  RequestInfo,
  SkipOptions,
  IgnoreSpec,
  IgnoreContext,
  IgnoreVerdict,
} from '@coraza/core'
import { buildIgnoreMatcher, consoleLogger, skipToIgnore } from '@coraza/core'
import type { Request, RequestHandler, Response } from 'express'

export interface CorazaExpressOptions {
  /**
   * A `WAF` (single instance, sync) or a `WAFPool` (worker_threads, async).
   * Pools scale linearly up to CPU count with a small latency overhead —
   * prefer them under production load. See @coraza/core for construction.
   *
   * Also accepts a promise of either, so modules that can't do top-level
   * await (CJS transpilers, Next middleware) can defer construction.
   */
  waf: WAFLike
  /**
   * Override how a block decision is turned into an HTTP response.
   * Default: sets status + plain-text body with the interruption's rule id.
   *
   * The optional `ctx.matchedRules` lists every rule that matched in the
   * transaction (only populated when `verboseLog: true`, otherwise
   * `undefined` to avoid the WASM round-trip on every block).
   */
  onBlock?: (
    interruption: Interruption,
    req: Request,
    res: Response,
    ctx?: CorazaBlockContext,
  ) => void
  /**
   * Inspect the response phase (headers + body) in addition to the request.
   * Default: `false`. Response inspection doubles per-request work; enable
   * only if you have response-side rules (e.g. data-leak detection).
   */
  inspectResponse?: boolean
  /**
   * Bypass Coraza for matching requests. The unified spec covers extensions,
   * route globs/regex, HTTP methods, body-size cutoffs, header equality,
   * and an imperative `match` escape hatch. Defaults skip common static
   * extensions; pass `{ skipDefaults: true }` to disable them, or
   * `false` to disable bypass altogether.
   *
   * See README "Skipping the WAF" for the field table.
   */
  ignore?: IgnoreSpec | false
  /**
   * @deprecated Use `ignore:` instead. The legacy `skip:` shape is mapped
   * to `ignore:` at construction and emits a one-shot deprecation warning.
   * Removed at stable 0.1.
   */
  skip?: SkipOptions | false
  /**
   * What to do if the WAF itself throws mid-request (WASM trap, pool
   * worker crash, bundle encoding error, etc.). Three forms:
   *
   *   'allow' — call next() and let the request through (fail-open).
   *   'block' — respond with 503 via onBlock (fail-closed, default).
   *   (err, ctx) => 'allow' | 'block' — per-error policy. ctx tracks
   *               `consecutiveErrors`, `totalErrors`, `since`. Lets you
   *               implement circuit-breaker / rate / per-error-class
   *               policy without `@coraza/express` enforcing one. A
   *               throwing policy falls back to 'block' (fail-closed).
   *
   * @default 'block'
   */
  onWAFError?: OnWAFErrorPolicy
  /**
   * When `true`, emit one `log.warn('coraza: matched', { ... })` per
   * matched rule on a block (ModSecurity error.log style). Adds an
   * extra `tx.matchedRules()` read on the block path; default `false`.
   * The default block log always includes `interruption.data`.
   */
  verboseLog?: boolean
}

/**
 * Optional context handed to `onBlock` as a fourth argument. Only
 * populated when `verboseLog: true` (the runner pre-fetches matched
 * rules for the verbose log path and re-uses them here).
 */
export interface CorazaBlockContext {
  matchedRules: MatchedRule[]
}

/**
 * Context handed to a function-form `onWAFError`. Counters are
 * adapter-instance-scoped (one per `coraza()` call); they don't reset
 * across instances and persist for the process lifetime.
 */
export interface OnWAFErrorContext {
  /** Errors since the last successful WAF evaluation (resets on success). */
  consecutiveErrors: number
  /** Process-lifetime error count for this adapter instance. */
  totalErrors: number
  /** Timestamp of the first error in the current consecutive run. */
  since: Date
}

export type OnWAFErrorPolicy =
  | 'allow'
  | 'block'
  | ((err: Error, ctx: OnWAFErrorContext) => 'allow' | 'block' | Promise<'allow' | 'block'>)

type ReqWithLog = Request & { log?: Logger }

const encoder = new TextEncoder()

export function coraza(options: CorazaExpressOptions): RequestHandler {
  const {
    waf: wafOrPromise,
    onBlock = defaultBlock,
    inspectResponse = false,
    onWAFError = 'block',
    verboseLog = false,
  } = options
  const matcher = resolveIgnoreMatcher(options.ignore, options.skip)

  // Resolve the (possibly deferred) WAF on first use and memoize. Accepting
  // a Promise keeps symmetry with @coraza/next's middleware shape and lets
  // callers avoid top-level await. The .catch(() => {}) is a no-op that
  // attaches a handler at factory time so a rejected waf promise doesn't
  // fire `unhandledRejection` before the first request arrives — each
  // request still awaits the same promise and sees the original error.
  const wafPromise = Promise.resolve(wafOrPromise)
  wafPromise.catch(() => {})
  let wafRef: AnyWAF | null = null
  const ensureWAF = async (): Promise<AnyWAF> => {
    if (wafRef) return wafRef
    wafRef = await wafPromise
    return wafRef
  }

  // Failure-history state for the function form of `onWAFError`. We
  // intentionally do NOT enforce a default circuit breaker — counters
  // are exposed verbatim to the consumer's policy.
  let consecutiveErrors = 0
  let totalErrors = 0
  let since = new Date(0)
  const onError = async (err: Error): Promise<'allow' | 'block'> => {
    if (consecutiveErrors === 0) since = new Date()
    consecutiveErrors++
    totalErrors++
    if (onWAFError === 'allow' || onWAFError === 'block') return onWAFError
    try {
      return await onWAFError(err, { consecutiveErrors, totalErrors, since })
    } catch {
      // A throwing policy must not become a request bypass.
      return 'block'
    }
  }
  const recordSuccess = (): void => {
    if (consecutiveErrors > 0) {
      consecutiveErrors = 0
      since = new Date(0)
    }
  }

  // `waf` is either a sync WAF or an async WAFPool. Both expose the same
  // surface (newTransaction / Transaction has the same method names). We
  // `await` every call so the middleware works against either.
  return async function corazaMiddleware(req, res, next) {
    const verdict = matcher === null ? false : matcher(buildIgnoreCtx(req))
    if (verdict === true) {
      next()
      return
    }
    let waf: AnyWAF
    try {
      waf = await ensureWAF()
    } catch (err) {
      // If the WAF promise itself rejects we can't open a transaction or
      // route through onBlock's logger. Treat as fail-closed by default.
      const log = (req as ReqWithLog).log ?? consoleLogger
      const e = err instanceof Error ? err : new Error(String(err))
      log.error('coraza: waf promise rejected', { err: e.message })
      const verdict = await onError(e)
      if (verdict === 'block' && !res.headersSent) {
        onBlock(
          { ruleId: 0, action: 'deny', status: 503, data: 'WAF unavailable', source: 'waf-error' },
          req,
          res,
        )
        return
      }
      next()
      return
    }
    const log = pickLogger(req as ReqWithLog, waf.logger)

    let tx: AnyTransaction
    try {
      tx = await waf.newTransaction()
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err))
      log.error('coraza: newTransaction failed', { err: e.message })
      const verdict = await onError(e)
      if (verdict === 'block' && !res.headersSent) {
        onBlock(
          { ruleId: 0, action: 'deny', status: 503, data: 'WAF unavailable', source: 'waf-error' },
          req,
          res,
        )
        return
      }
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
      const bodyBuf = verdict === 'skip-body' ? undefined : extractBody(req)
      const interrupted = await tx.processRequestBundle(reqInfo, bodyBuf)
      if (interrupted) {
        // A genuine block is still a successful WAF evaluation — counters reset.
        recordSuccess()
        return emitBlock(await tx.interruption(), req, res, onBlock, log, tx, verboseLog)
      }
      // Request passed cleanly — counters reset.
      recordSuccess()

      if (inspectResponse) {
        // Response hooks patch res.writeHead / res.end synchronously. They
        // only work with the sync `WAF` path — a pool's async methods can't
        // block mid-write. Skip quietly under pools; log once so users know.
        if (isSyncTx(tx)) {
          hookResponse(
            tx,
            res,
            (it) => {
              // Sync-only path; emit synchronously so we don't return a
              // Promise from res.writeHead/res.end.
              const mr = verboseLog ? tx.matchedRules() : undefined
              if (it) emitBlockSync(it, req, res, onBlock, log, mr)
            },
            log,
          )
        } else {
          log.warn(
            'coraza: inspectResponse=true is a no-op when using WAFPool; use a single WAF or drop response inspection',
          )
        }
      }

      next()
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err))
      log.error('coraza: middleware error', { err: e.message })
      const verdict = await onError(e)
      if (verdict === 'block') {
        // Fail-closed: synthesize a 503 block verdict so a crash in the
        // WAF can't be weaponized into a bypass.
        if (!res.headersSent) {
          onBlock(
            { ruleId: 0, action: 'deny', status: 503, data: 'WAF internal error', source: 'waf-error' },
            req,
            res,
          )
        }
        return
      }
      next()
    }
  }
}

// A union of Transaction (sync) and WorkerTransaction (async) — both have
// the same method names; differing return types get uniformly awaited.
type AnyTransaction = Awaited<ReturnType<AnyWAF['newTransaction']>>

/**
 * Resolve the per-request ignore matcher from the new `ignore` option,
 * falling back to the deprecated `skip` shape (with a one-shot warning).
 * Returns `null` when bypass is explicitly disabled.
 */
function resolveIgnoreMatcher(
  ignore: IgnoreSpec | false | undefined,
  skip: SkipOptions | false | undefined,
): ((ctx: IgnoreContext) => IgnoreVerdict) | null {
  if (ignore === false || skip === false) return null
  if (ignore !== undefined) return buildIgnoreMatcher(ignore)
  const mapped = skipToIgnore(skip)
  if (skip !== undefined && !legacyWarnedExpress) {
    legacyWarnedExpress = true
    // eslint-disable-next-line no-console
    console.warn(
      'coraza: the `skip:` option is deprecated and will be removed at stable 0.1; ' +
        'migrate to `ignore: { extensions, routes, methods, bodyLargerThan, headerEquals, match }`.',
    )
  }
  return buildIgnoreMatcher(mapped)
}

let legacyWarnedExpress = false

function buildIgnoreCtx(req: Request): IgnoreContext {
  const url = parseUrl(req)
  const cl = parseContentLength(req.headers['content-length'])
  const headers = req.headers as unknown as Record<string, string | string[] | undefined>
  const map = new Map<string, string>()
  for (const k in headers) {
    const v = headers[k]
    if (v === undefined) continue
    map.set(k, Array.isArray(v) ? v.join(',') : v)
  }
  return Object.freeze({
    method: req.method,
    url,
    headers: map,
    contentLength: cl,
  })
}

function parseUrl(req: Request): URL {
  // Prefer originalUrl for routers; fall back to url. Express paths are
  // path-only ("/api/x?q=1"); URL needs a base. Hardcoding 'http://x' keeps
  // pathname/search exact and avoids a real socket lookup hot-path.
  const raw = req.originalUrl || req.url || '/'
  try {
    return new URL(raw, 'http://x')
  } catch {
    /* c8 ignore next 2 — defensive: URL with a base origin succeeds for any
       string we'd see from Express; fallback so a malformed URL never throws into the catch-and-next path. */
    return new URL('/', 'http://x')
  }
}

function parseContentLength(v: string | string[] | undefined): number | null {
  if (v === undefined) return null
  const s = Array.isArray(v) ? v[0]! : v
  const n = Number(s)
  return Number.isFinite(n) && n >= 0 ? n : null
}


export function defaultBlock(interruption: Interruption, _req: Request, res: Response): void {
  if (res.headersSent) return
  res
    .status(interruption.status || 403)
    .type('text/plain')
    .send(`Request blocked by Coraza (rule ${interruption.ruleId})\n`)
}

async function emitBlock(
  interruption: Interruption | null,
  req: Request,
  res: Response,
  onBlock: NonNullable<CorazaExpressOptions['onBlock']>,
  log: Logger,
  tx: AnyTransaction,
  verboseLog: boolean,
): Promise<void> {
  /* c8 ignore next — defensive: tx_has_interrupt=1 but get_interrupt=null is a bug */
  if (!interruption) return
  const matched = verboseLog ? await tx.matchedRules() : undefined
  emitBlockSync(interruption, req, res, onBlock, log, matched)
}

function emitBlockSync(
  interruption: Interruption,
  req: Request,
  res: Response,
  onBlock: NonNullable<CorazaExpressOptions['onBlock']>,
  log: Logger,
  matched: MatchedRule[] | undefined,
): void {
  log.warn('coraza: request blocked', {
    ruleId: interruption.ruleId,
    status: interruption.status,
    action: interruption.action,
    ...(interruption.data ? { data: interruption.data } : {}),
  })
  if (matched) {
    for (const r of matched) {
      log.warn('coraza: matched', {
        ruleId: r.id,
        severity: r.severity,
        msg: r.message,
      })
    }
    onBlock(interruption, req, res, { matchedRules: matched })
  } else {
    // Don't pass `undefined` as a 4th arg — keeps toHaveBeenCalledWith(it, req, res)
    // assertions in pre-existing consumer tests stable.
    onBlock(interruption, req, res)
  }
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

// A Transaction (sync) vs a WorkerTransaction (async): the worker variant's
// methods are defined with `async`, so `close.constructor.name` is
// 'AsyncFunction'; the sync Transaction's methods are plain functions.
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

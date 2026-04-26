// WAFPool — N worker threads, each holding a WAF instance. Requests are
// pinned to their worker for the duration of the transaction. Used when
// the main event loop can't keep up with Coraza's per-request CPU cost.
//
// Trade-off: calls become async (MessagePort round-trip adds ~20-50 µs
// per process* call on hot Node versions). Worth it once rule evaluation
// starts serializing ahead of response latency.
//
// Usage:
//
//   const pool = await createWAFPool({ size: os.availableParallelism(), ...config })
//   const tx = await pool.newTransaction()
//   if (await tx.processRequestBundle({ ... }, body)) {
//     const it = await tx.interruption()
//     // block
//   }
//   await tx.close()

import { Worker } from 'node:worker_threads'
import { fileURLToPath } from 'node:url'
import { consoleLogger } from './logger.js'
import { compileWasmModule } from './wasm.js'
import { defaultWasmPath, defaultPoolWorkerPath } from './wasmResolve.js'
import type {
  Interruption,
  Logger,
  MatchedRule,
  RequestInfo,
  ResponseInfo,
  WAFConfig,
} from './types.js'

export interface WAFPoolOptions extends WAFConfig {
  /** Number of worker threads. Default: `os.availableParallelism()`. */
  size?: number
  /**
   * Rotate a worker after it has served this many transactions. The WAF
   * instance is destroyed and a fresh one spawned in its place. Caps the
   * long-term memory footprint of each worker — Coraza's per-request
   * allocations aren't all freed (WASM linear memory, Go GC pressure,
   * scratch buffers), so a process running forever trends up even when
   * every individual transaction is clean. Default: `50000`. Set `0` or
   * `Infinity` to disable rotation.
   */
  maxRequestsPerWorker?: number
  /**
   * Maximum time (ms) to wait for every worker to come online and ack the
   * `init` handshake before `createWAFPool` rejects. Default: `10000`
   * (10 s). Pass `0` or `Infinity` to disable (legacy hang-forever
   * behaviour — not recommended).
   *
   * Why this exists: some bundlers (e.g. Turbopack in Next.js 16 dev
   * mode) emit the worker file with ESM `import` syntax but without a
   * sibling `"type": "module"` marker and without a `.mjs` extension, so
   * Node refuses to load it. The worker never emits `online`, `error`,
   * or `exit`, and `createWAFPool` would otherwise await forever. This
   * timeout converts that silent hang into a loud, actionable error
   * that names the likely culprit.
   */
  readyTimeoutMs?: number
}

const DEFAULT_MAX_REQUESTS_PER_WORKER = 50_000

/**
 * How long to wait for every worker to come `online` and ack its `init`
 * message before we reject `createWAFPool` with an actionable error. The
 * pool normally boots in ~100-300 ms on a modern box; 10 s is well past
 * that for any realistic machine while still tripping fast enough that
 * an adapter's own timeout (e.g. Express' default 2-minute socket
 * timeout) doesn't hide the failure. Exposed as an option for CI / slow
 * containers that legitimately need longer (or `0` / `Infinity` to
 * disable — never recommended; a hung pool is indistinguishable from a
 * bundler that emitted the worker with the wrong module format).
 */
const DEFAULT_POOL_READY_TIMEOUT_MS = 10_000

interface Pending {
  resolve(value: unknown): void
  reject(err: Error): void
}

interface WorkerSlot {
  worker: Worker
  pending: Map<number, Pending>
  ready: Promise<void>
  busy: number
  /** Total transactions ever dispatched to this worker (monotonic). */
  requests: number
  /** Rotation latch — flips true once a replacement has been scheduled. */
  rotating: boolean
  /** Resolves when this slot is fully drained and terminated. */
  drained: Promise<void> | null
}

let nextReqId = 1

export class WAFPool {
  readonly size: number
  readonly logger: Logger
  readonly mode: NonNullable<WAFConfig['mode']>
  readonly maxRequestsPerWorker: number

  #slots: WorkerSlot[]
  #rr = 0
  #destroyed = false
  /** Raw WAFConfig used to spin up replacement workers during rotation. */
  #workerConfig: WAFConfig
  /**
   * WASM module compiled once on the main thread, shared with every worker
   * via structured clone (transfers by reference in V8, carrying compiled
   * code). Workers skip the ~200-400 ms compile step and go straight to
   * instantiate. Reused across rotations too.
   */
  #wasmModule: WebAssembly.Module | undefined
  /** Draining slots — kept alive until their in-flight tx's finish. */
  #draining = new Set<WorkerSlot>()
  /** Monotonic id for log correlation when a rotation fires. */
  #rotationId = 0

  private constructor(
    slots: WorkerSlot[],
    logger: Logger,
    mode: NonNullable<WAFConfig['mode']>,
    workerConfig: WAFConfig,
    maxRequestsPerWorker: number,
    wasmModule: WebAssembly.Module | undefined,
  ) {
    this.#slots = slots
    this.size = slots.length
    this.logger = logger
    this.mode = mode
    this.#workerConfig = workerConfig
    this.maxRequestsPerWorker = maxRequestsPerWorker
    this.#wasmModule = wasmModule
  }

  static async create(opts: WAFPoolOptions): Promise<WAFPool> {
    const { size: requested, maxRequestsPerWorker, readyTimeoutMs, ...config } = opts
    const size = Math.max(1, requested ?? defaultSize())
    const logger = config.logger ?? consoleLogger
    const mode = config.mode ?? 'detect'
    const maxReqs =
      maxRequestsPerWorker === undefined
        ? DEFAULT_MAX_REQUESTS_PER_WORKER
        : maxRequestsPerWorker === 0 || !Number.isFinite(maxRequestsPerWorker)
          ? Infinity
          : Math.max(1, Math.floor(maxRequestsPerWorker))
    const readyTimeout =
      readyTimeoutMs === undefined
        ? DEFAULT_POOL_READY_TIMEOUT_MS
        : readyTimeoutMs === 0 || !Number.isFinite(readyTimeoutMs)
          ? Infinity
          : Math.max(1, Math.floor(readyTimeoutMs))

    // Compile the WASM module once on the main thread and share it with
    // every worker via workerData (structured clone preserves the compiled
    // module by reference in Node 22+). Without this, each worker would
    // independently re-compile the ~5 MB binary: Node has no cross-worker
    // code cache for local files (nodejs/node#36671). Respects an already
    // pre-compiled module supplied by the caller.
    const wasmModule =
      config.wasmModule ??
      (await compileWasmModule(config.wasmSource ?? defaultWasmPath()))
    // Forward the compiled module to each worker via WAFConfig. No need to
    // also ship `wasmSource` — the worker's createWAF short-circuits on
    // `wasmModule` before reading any bytes. Strip `logger` because it
    // carries function references and structured clone (MessagePort) can't
    // transfer those — workers log through their own consoleLogger.
    const { logger: _workerLoggerStripped, ...configCloneable } = config
    void _workerLoggerStripped
    const workerConfig: WAFConfig = { ...configCloneable, wasmModule }

    const slots: WorkerSlot[] = []
    for (let i = 0; i < size; i++) slots.push(spawnSlot(logger, wasmModule))

    // Init every worker in parallel, reject fast if any fails.
    //
    // Wrapped in a hard deadline: if a bundler has emitted the worker file
    // with ESM syntax but without an ESM marker (no `.mjs` extension and
    // no sibling `"type": "module"`), Node fails to load it silently —
    // the worker never emits `online`, `error`, or `exit`, and
    // `slot.ready` hangs forever. Turbopack in Next.js 16 dev mode is the
    // canonical repro; see github.com/coraza-incubator/coraza-node#8. Convert the
    // hang into a loud error that tells the operator what to check.
    try {
      await withTimeout(
        Promise.all(
          slots.map((slot) =>
            slot.ready.then(() => callSlot<void>(slot, { type: 'init', config: workerConfig })),
          ),
        ),
        readyTimeout,
        () =>
          new Error(
            `coraza: pool workers failed to initialize within ${readyTimeout}ms. ` +
              `This usually means the bundler emitted the pool worker without an ESM marker ` +
              `(Node needs either a .mjs extension or a sibling package.json with ` +
              `"type":"module"). Known culprit: Next.js 16 Turbopack dev mode. ` +
              `Workaround: use createWAF (single-threaded) or a bundler-specific opt-out. ` +
              `Pass readyTimeoutMs to override this deadline.`,
          ),
      )
    } catch (err) {
      // Tear down any workers we did manage to spawn — otherwise they'd
      // keep the event loop alive after the caller's `createWAFPool`
      // promise rejects.
      await Promise.allSettled(
        slots.map(async (slot) => {
          try {
            await slot.worker.terminate()
          } catch {
            /* ignore */
          }
        }),
      )
      throw err
    }

    const pool = new WAFPool(slots, logger, mode, workerConfig, maxReqs, wasmModule)

    // Pre-warm: send a synthetic request through every worker so V8 JITs
    // the WASM hot paths before real traffic arrives. Cuts first-request
    // p99 meaningfully (the first real request otherwise pays JIT cost).
    // Best-effort — any worker that rejects just logs and moves on.
    await Promise.all(
      slots.map(async (_slot, i) => {
        try {
          const tx = await pool.newTransaction()
          try {
            // Fused bundle exercises phases 1+2 so both rule sets get JITed.
            await tx.processRequestBundle(
              {
                method: 'GET',
                url: '/__coraza_prewarm',
                protocol: 'HTTP/1.1',
                headers: [['host', 'prewarm.local']],
                remoteAddr: '127.0.0.1',
                remotePort: 0,
                serverPort: 0,
              },
              'prewarm-body',
            )
          } finally {
            await tx.close()
          }
        } catch (err) {
          logger.warn('coraza pool: prewarm failed on worker', {
            worker: i,
            err: (err as Error).message,
          })
        }
      }),
    )

    return pool
  }

  /**
   * Start a new transaction on the next worker (round-robin). The returned
   * WorkerTransaction is pinned to that worker — all its process*() calls
   * go to the same thread for correctness.
   */
  async newTransaction(): Promise<WorkerTransaction> {
    if (this.#destroyed) throw new Error('coraza: pool is destroyed')
    const slot = this.#pickSlot()
    slot.requests++
    const { txId } = await callSlot<{ txId: number }>(slot, { type: 'newTx' })
    slot.busy++
    // Check rotation threshold after the successful handoff so a failed
    // newTx doesn't burn a rotation slot. The newly-created tx is pinned
    // to `slot`; rotating it out of #slots won't affect this caller.
    if (
      !slot.rotating &&
      Number.isFinite(this.maxRequestsPerWorker) &&
      slot.requests >= this.maxRequestsPerWorker
    ) {
      this.#scheduleRotation(slot)
    }
    return new WorkerTransaction(slot, txId)
  }

  /** Graceful shutdown — wait for every worker to ack, then terminate. */
  async destroy(): Promise<void> {
    if (this.#destroyed) return
    this.#destroyed = true
    const active = [...this.#slots, ...this.#draining]
    this.#draining.clear()
    await Promise.all(
      active.map(async (slot) => {
        try {
          await callSlot<void>(slot, { type: 'shutdown' })
        } catch {
          /* worker may have already exited */
        }
        await slot.worker.terminate()
      }),
    )
  }

  get destroyed(): boolean {
    return this.#destroyed
  }

  /**
   * threadIds of the currently-live worker slots (not including draining
   * ones being rotated out). Exposed for observability — a rotation changes
   * one of these values, so operators can graph worker churn.
   */
  threadIds(): number[] {
    return this.#slots.map((s) => s.worker.threadId)
  }

  // Pick the least-busy slot; fall back to round-robin on ties. This keeps
  // long-running rules from hot-spotting a single worker.
  #pickSlot(): WorkerSlot {
    let best = this.#slots[this.#rr % this.#slots.length]!
    let bestBusy = best.busy
    for (const s of this.#slots) {
      if (s.busy < bestBusy) {
        best = s
        bestBusy = s.busy
      }
    }
    this.#rr++
    return best
  }

  /**
   * Spawn a replacement worker in the background and, once it's ready +
   * initialized, atomically swap it into `#slots` at `old`'s current index.
   * The old slot is then drained: we wait until every in-flight tx finishes
   * (busy -> 0 and pending map empty), then shut it down and terminate.
   *
   * This must not drop any in-flight request. The `WorkerTransaction`
   * objects returned before the swap hold a direct reference to `old`, so
   * their process*() and close() calls still reach the old worker. New
   * transactions route to the replacement only (we removed `old` from
   * `#slots`, so `#pickSlot` can't see it).
   */
  #scheduleRotation(old: WorkerSlot): void {
    old.rotating = true
    const id = ++this.#rotationId
    const drained = (async () => {
      const replacement = spawnSlot(this.logger, this.#wasmModule)
      try {
        await replacement.ready
        await callSlot<void>(replacement, { type: 'init', config: this.#workerConfig })
      } catch (err) {
        this.logger.error('coraza pool: rotation replacement failed to init; keeping old worker', {
          rotationId: id,
          err: (err as Error).message,
        })
        old.rotating = false
        try {
          await replacement.worker.terminate()
        } catch {
          /* ignore */
        }
        return
      }

      // Swap: find `old` in #slots (its index may have shifted if some other
      // rotation completed first). If it's already gone, we're late — just
      // drain without swapping.
      const idx = this.#slots.indexOf(old)
      if (idx >= 0 && !this.#destroyed) {
        this.#slots[idx] = replacement
        this.#draining.add(old)
        this.logger.info('coraza pool: rotating worker', {
          rotationId: id,
          slot: idx,
          requests: old.requests,
          threshold: this.maxRequestsPerWorker,
        })
      } else {
        // Pool already destroyed or slot vanished — terminate the fresh one.
        try {
          await callSlot<void>(replacement, { type: 'shutdown' })
        } catch {
          /* ignore */
        }
        await replacement.worker.terminate()
        return
      }

      // Drain the old slot: wait for busy==0 and no pending messages.
      await waitForDrain(old)

      try {
        await callSlot<void>(old, { type: 'shutdown' })
      } catch {
        /* worker may have already exited */
      }
      try {
        await old.worker.terminate()
      } catch {
        /* ignore */
      }
      this.#draining.delete(old)
      this.logger.info('coraza pool: rotation complete', { rotationId: id })
    })()
    old.drained = drained
    // Surface any unexpected rejection rather than silently swallowing.
    drained.catch((err) => {
      this.logger.error('coraza pool: rotation failed', {
        rotationId: id,
        err: (err as Error).message,
      })
    })
  }
}

async function waitForDrain(slot: WorkerSlot): Promise<void> {
  // Poll in short intervals. The transactions that block us finish via
  // `close()` which decrements busy; pending also clears on each reply.
  // 5 ms is small enough that rotation completes promptly once traffic
  // quiets, and large enough that a fully-busy pool doesn't burn CPU
  // spinning on the check.
  while (slot.busy > 0 || slot.pending.size > 0) {
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}

export async function createWAFPool(opts: WAFPoolOptions): Promise<WAFPool> {
  return WAFPool.create(opts)
}

/**
 * Transaction handle for a pooled WAF. Mirrors the sync `Transaction` API
 * but every method returns a Promise (MessagePort round-trip).
 */
export class WorkerTransaction {
  #slot: WorkerSlot
  #txId: number
  #closed = false

  constructor(slot: WorkerSlot, txId: number) {
    this.#slot = slot
    this.#txId = txId
  }

  /** Fused request phase — one worker round-trip instead of 2-5. */
  async processRequestBundle(
    req: RequestInfo,
    body: Uint8Array | string | undefined,
  ): Promise<boolean> {
    const { interrupted } = await this.#proc('requestBundle', { req, body })
    return interrupted
  }

  async processResponse(res: ResponseInfo): Promise<boolean> {
    const { interrupted } = await this.#proc('response', res)
    return interrupted
  }

  async processResponseBody(body?: Uint8Array | string): Promise<boolean> {
    const { interrupted } = await this.#proc('responseBody', body)
    return interrupted
  }

  async processLogging(): Promise<void> {
    if (this.#closed) return
    await this.#proc('logging', undefined)
  }

  async interruption(): Promise<Interruption | null> {
    const r = await callSlot<{ value: Interruption | null }>(this.#slot, {
      type: 'get',
      txId: this.#txId,
      which: 'interruption',
    })
    return r.value
  }

  async matchedRules(): Promise<MatchedRule[]> {
    const r = await callSlot<{ value: MatchedRule[] }>(this.#slot, {
      type: 'get',
      txId: this.#txId,
      which: 'matchedRules',
    })
    return r.value ?? []
  }

  async isRuleEngineOff(): Promise<boolean> {
    return this.#pred('ruleEngineOff')
  }
  async isRequestBodyAccessible(): Promise<boolean> {
    return this.#pred('reqBodyAccessible')
  }
  async isResponseBodyAccessible(): Promise<boolean> {
    return this.#pred('respBodyAccessible')
  }
  async isResponseBodyProcessable(): Promise<boolean> {
    return this.#pred('respBodyProcessable')
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    try {
      await callSlot<void>(this.#slot, { type: 'close', txId: this.#txId })
    } finally {
      this.#slot.busy = Math.max(0, this.#slot.busy - 1)
    }
  }

  /**
   * Reset the transaction inside the worker so this same handle can be
   * reused for the next request. Cheaper than `close()` + `newTransaction()`
   * under keep-alive — saves one MessagePort round-trip and reuses the
   * worker-side scratch buffers.
   */
  async reset(): Promise<void> {
    if (this.#closed) throw new Error('coraza: transaction is closed')
    await callSlot<void>(this.#slot, { type: 'reset', txId: this.#txId })
  }

  get closed(): boolean {
    return this.#closed
  }

  async #proc(
    op: 'requestBundle' | 'response' | 'responseBody' | 'logging',
    args: unknown,
  ): Promise<{ interrupted: boolean }> {
    const r = await callSlot<{ interrupted?: boolean }>(this.#slot, {
      type: 'proc',
      txId: this.#txId,
      op,
      args,
    })
    return { interrupted: Boolean(r.interrupted) }
  }

  async #pred(
    which: 'ruleEngineOff' | 'reqBodyAccessible' | 'respBodyAccessible' | 'respBodyProcessable',
  ): Promise<boolean> {
    const r = await callSlot<{ value: boolean }>(this.#slot, {
      type: 'pred',
      txId: this.#txId,
      which,
    })
    return r.value
  }
}

function defaultSize(): number {
  // os.availableParallelism() is Node 19+; fall back on cpus().
  const os = require('node:os') as typeof import('node:os')
  return typeof os.availableParallelism === 'function'
    ? os.availableParallelism()
    : os.cpus().length
}

async function withTimeout<T>(
  p: Promise<T>,
  ms: number,
  mkErr: () => Error,
): Promise<T> {
  if (!Number.isFinite(ms)) return p
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      p,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(mkErr()), ms)
        // Don't keep the event loop alive just for this watchdog; if the
        // pool promise is going to resolve, the timer is redundant.
        if (typeof (timer as unknown as { unref?: () => void }).unref === 'function') {
          ;(timer as unknown as { unref: () => void }).unref()
        }
      }),
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function spawnSlot(logger: Logger, wasmModule?: WebAssembly.Module): WorkerSlot {
  // `.mjs` so Node treats the worker as ESM regardless of what the
  // surrounding bundler (Turbopack, webpack, etc.) does with package.json
  // markers. See github.com/coraza-incubator/coraza-node#8.
  // defaultPoolWorkerPath() has the same createRequire fallback as
  // defaultWasmPath so Next.js 15's middleware bundler (which rewrites
  // import.meta.url) doesn't explode on pool boot.
  const workerUrl = defaultPoolWorkerPath()
  // fileURLToPath() throws ERR_INVALID_ARG_TYPE when the URL is an
  // instance of a bundler-duplicated URL class (webpack under Next 15
  // middleware). Fall back to manual pathname decode — works across
  // every bundler because it touches no classes.
  let workerPath: string
  try {
    workerPath = fileURLToPath(workerUrl)
  } catch {
    workerPath = decodeURIComponent(workerUrl.pathname)
  }
  const worker = new Worker(workerPath, {
    // Don't inherit the parent's loader args (e.g. --import tsx) — the worker
    // runs the pre-compiled pool-worker.mjs and doesn't need the TS loader.
    execArgv: [],
    // Structured clone carries the compiled WebAssembly.Module by reference
    // so the worker skips its own compile step.
    workerData: wasmModule ? { wasmModule } : undefined,
  })
  const pending = new Map<number, Pending>()
  const slot: WorkerSlot = {
    worker,
    pending,
    busy: 0,
    requests: 0,
    rotating: false,
    drained: null,
    ready: new Promise<void>((resolve, reject) => {
      worker.once('online', () => resolve())
      worker.once('error', (e) => reject(e))
    }),
  }

  worker.on('message', (msg: { reqId: number; ok: boolean; error?: string; [k: string]: unknown }) => {
    const p = pending.get(msg.reqId)
    if (!p) {
      if (msg.reqId === -1) logger.error(String(msg.error ?? 'worker error'))
      return
    }
    pending.delete(msg.reqId)
    if (msg.ok) p.resolve(msg)
    else p.reject(new Error(msg.error ?? 'worker error'))
  })

  worker.on('error', (err) => {
    const e = err instanceof Error ? err : new Error(String(err))
    for (const p of pending.values()) p.reject(e)
    pending.clear()
  })

  // `worker.on('error')` fires on thrown errors but NOT on a clean
  // `process.exit()` from inside the worker (e.g. an unhandledRejection
  // branch that aborts). Without this, in-flight callers await forever
  // and their request/body closures stay live. Reject every pending
  // promise on exit so callers surface a real failure and let the GC
  // reclaim the captured buffers.
  worker.on('exit', (code) => {
    if (pending.size === 0) return
    const err = new Error(`coraza: pool worker exited (code ${code})`)
    for (const p of pending.values()) p.reject(err)
    pending.clear()
  })

  return slot
}

async function callSlot<T>(slot: WorkerSlot, msg: Record<string, unknown>): Promise<T> {
  const reqId = nextReqId++
  return new Promise<T>((resolve, reject) => {
    slot.pending.set(reqId, { resolve: resolve as (v: unknown) => void, reject })
    slot.worker.postMessage({ ...msg, reqId })
  })
}

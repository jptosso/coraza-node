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
}

interface Pending {
  resolve(value: unknown): void
  reject(err: Error): void
}

interface WorkerSlot {
  worker: Worker
  pending: Map<number, Pending>
  ready: Promise<void>
  busy: number
}

let nextReqId = 1

export class WAFPool {
  readonly size: number
  readonly logger: Logger
  readonly mode: NonNullable<WAFConfig['mode']>

  #slots: WorkerSlot[]
  #rr = 0
  #destroyed = false

  private constructor(slots: WorkerSlot[], logger: Logger, mode: NonNullable<WAFConfig['mode']>) {
    this.#slots = slots
    this.size = slots.length
    this.logger = logger
    this.mode = mode
  }

  static async create(opts: WAFPoolOptions): Promise<WAFPool> {
    const { size: requested, ...config } = opts
    const size = Math.max(1, requested ?? defaultSize())
    const logger = config.logger ?? consoleLogger
    const mode = config.mode ?? 'detect'

    // Compile the WASM module once on the main thread and share it with
    // every worker via workerData (structured clone preserves the compiled
    // module by reference in Node 22+). Without this, each worker would
    // independently re-compile the ~5 MB binary: Node has no cross-worker
    // code cache for local files (nodejs/node#36671). Respects an already
    // pre-compiled module supplied by the caller.
    const wasmModule =
      config.wasmModule ??
      (await compileWasmModule(
        config.wasmSource ?? new URL('./wasm/coraza.wasm', import.meta.url),
      ))
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
    await Promise.all(
      slots.map((slot) =>
        slot.ready.then(() => callSlot<void>(slot, { type: 'init', config: workerConfig })),
      ),
    )

    const pool = new WAFPool(slots, logger, mode)

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
    const { txId } = await callSlot<{ txId: number }>(slot, { type: 'newTx' })
    slot.busy++
    return new WorkerTransaction(slot, txId)
  }

  /** Graceful shutdown — wait for every worker to ack, then terminate. */
  async destroy(): Promise<void> {
    if (this.#destroyed) return
    this.#destroyed = true
    await Promise.all(
      this.#slots.map(async (slot) => {
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

function spawnSlot(logger: Logger, wasmModule?: WebAssembly.Module): WorkerSlot {
  const workerUrl = new URL('./pool-worker.js', import.meta.url)
  const worker = new Worker(fileURLToPath(workerUrl), {
    // Don't inherit the parent's loader args (e.g. --import tsx) — the worker
    // runs the pre-compiled pool-worker.js and doesn't need the TS loader.
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
    for (const p of pending.values()) p.reject(err)
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

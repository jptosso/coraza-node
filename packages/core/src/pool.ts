// WAFPool — N worker threads, each holding a WAF instance. Requests are
// pinned to their worker for the duration of the transaction. Used when
// the main event loop can't keep up with Coraza's per-request CPU cost.
//
// Hot path uses a per-slot SharedArrayBuffer + Atomics.waitAsync handshake
// to ship the encoded request bundle to the worker. This sidesteps the
// ~20-50 µs structured-clone + MessagePort round-trip the pre-existing
// postMessage path paid on every processRequestBundle call. Cold paths
// (newTx, close, logging, response-body) stay on postMessage — they're
// either rare or already carry a WASM call cost that dwarfs the clone.
//
// Bundles that overflow the 1 MiB scratch region (large bodies) fall
// back to postMessage so oversized requests keep working end-to-end.
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
import { encodeRequestBundle } from './transaction.js'
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

// Per-slot SAB control word layout (Int32). Sized for a single in-flight
// request per slot — the pool's least-busy dispatch keeps us honest there.
const CTRL_REQ_SEQ = 0
const CTRL_REQ_LEN = 1
const CTRL_REQ_TX_ID = 2 // worker-side tx id this bundle targets
const CTRL_RESP_SEQ = 3
const CTRL_RESP_RC = 4 // 0=ok, 1=interrupted, -1=error
const CTRL_RESP_INT_LEN = 5 // length of interruption JSON bytes written at data[0..]
const CTRL_RESP_ERR_LEN = 6 // length of error message bytes written at data[0..]
const CTRL_I32_SIZE = 16 // 64 bytes, oversized so future additions don't resize the SAB

const DATA_SAB_BYTES = 1 << 20 // 1 MiB per-slot scratch for the request bundle
const SAB_TIMEOUT_MS = 5_000 // fail-closed ceiling for the Atomics handshake

// The encoded-header scratch the bundle encoder reuses across calls on the
// main thread. Lives on the slot so a worker that falls back to postMessage
// still benefits from the amortised allocation.
interface HeaderBufRef { current: Uint8Array }

interface WorkerSlot {
  worker: Worker
  pending: Map<number, Pending>
  ready: Promise<void>
  busy: number
  // SAB handshake state. `null` for slots that haven't finished init —
  // callSlot() will postMessage through in that window.
  sabData: SharedArrayBuffer | null
  sabCtrl: SharedArrayBuffer | null
  sabDataU8: Uint8Array | null
  sabCtrlI32: Int32Array | null
  sabReqSeq: number
  sabRespSeq: number
  sabHeaderBuf: HeaderBufRef
  // Guards the one-in-flight invariant: if a SAB request is pending we
  // queue any follow-up on the same slot behind it. `busy` only tracks
  // transactions; this tracks the SAB handshake specifically.
  sabQueue: Promise<unknown>
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

    const slots: WorkerSlot[] = []
    for (let i = 0; i < size; i++) slots.push(spawnSlot(logger))

    // Init every worker in parallel, reject fast if any fails. The init
    // message carries the SAB handles; the worker's Atomics-waitAsync
    // loop starts the moment it receives them.
    await Promise.all(
      slots.map((slot) =>
        slot.ready.then(() =>
          callSlot<void>(slot, {
            type: 'init',
            config,
            sabData: slot.sabData,
            sabCtrl: slot.sabCtrl,
          }),
        ),
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
 * but every method returns a Promise.
 *
 * `processRequestBundle` tries the SAB fast path first: encode the bundle
 * into the slot's shared scratch buffer, signal the worker via Atomics,
 * wait on the reply with Atomics.waitAsync (5 s timeout; timeouts
 * surface as errors the adapter turns into a 503 fail-closed). Oversized
 * bundles fall back to structured-clone over postMessage.
 */
export class WorkerTransaction {
  #slot: WorkerSlot
  #txId: number
  #closed = false
  // Cached interruption JSON decoded from the SAB response region after a
  // fast-path processRequestBundle. Lets interruption() answer without a
  // postMessage hop when the worker already wrote the verdict in-band.
  #cachedInterruption: Interruption | null | undefined = undefined

  constructor(slot: WorkerSlot, txId: number) {
    this.#slot = slot
    this.#txId = txId
  }

  /** Fused request phase — one worker round-trip instead of 2-5. */
  async processRequestBundle(
    req: RequestInfo,
    body: Uint8Array | string | undefined,
  ): Promise<boolean> {
    if (this.#closed) throw new Error('coraza: transaction is closed')
    // Serialise SAB requests on this slot so we never race two bundles
    // through the same shared region. WorkerTransaction is single-flight
    // per request in practice, but a caller holding two transactions on
    // one slot (pool.newTransaction() happened to pick the same worker
    // twice under busy-pressure) could otherwise collide.
    const run = async (): Promise<boolean> => this.#runBundle(req, body)
    const next = this.#slot.sabQueue.then(run, run)
    // Swallow rejection on the queue; individual callers handle their own.
    this.#slot.sabQueue = next.catch(() => {})
    return next
  }

  async #runBundle(
    req: RequestInfo,
    body: Uint8Array | string | undefined,
  ): Promise<boolean> {
    const slot = this.#slot
    const dataU8 = slot.sabDataU8
    const ctrlI32 = slot.sabCtrlI32
    // Fallback: SAB wasn't installed (shouldn't happen after init) or the
    // bundle overflows our 1 MiB scratch. Structured-clone over postMessage
    // keeps oversize / pre-init requests flowing end-to-end.
    if (!dataU8 || !ctrlI32) return this.#procFallback(req, body)

    const encoded = encodeRequestBundle(req, body, slot.sabHeaderBuf, dataU8)
    // If the encoder allocated a fresh buffer, we overflowed the SAB.
    // `encoded.buffer` will be a plain ArrayBuffer, not the SharedArrayBuffer.
    if (encoded.buffer !== dataU8.buffer) return this.#procFallback(req, body)

    const len = encoded.length
    const seq = ++slot.sabReqSeq

    Atomics.store(ctrlI32, CTRL_REQ_LEN, len)
    Atomics.store(ctrlI32, CTRL_REQ_TX_ID, this.#txId)
    Atomics.store(ctrlI32, CTRL_RESP_INT_LEN, 0)
    Atomics.store(ctrlI32, CTRL_RESP_ERR_LEN, 0)
    Atomics.store(ctrlI32, CTRL_RESP_RC, 0)
    // Publish the new request sequence last so the worker sees a fully
    // populated control word. storeInt32 ordering is a full fence.
    Atomics.store(ctrlI32, CTRL_REQ_SEQ, seq)
    Atomics.notify(ctrlI32, CTRL_REQ_SEQ, 1)

    const expectedResp = slot.sabRespSeq + 1
    const waitRes = waitAsync(ctrlI32, CTRL_RESP_SEQ, slot.sabRespSeq, SAB_TIMEOUT_MS)
    const res = waitRes.async ? await waitRes.value : waitRes.value
    if (res === 'timed-out') {
      // Fail-closed: surface as an error so the adapter's onWAFError='block'
      // path yields a 503. Never let a hung worker turn into a silent bypass.
      throw new Error('coraza: pool worker SAB wait timed out')
    }
    // Defensive: someone else bumped the seq. Our one-in-flight serialisation
    // should prevent this, but re-align and fail-closed if it ever happens.
    slot.sabRespSeq = Atomics.load(ctrlI32, CTRL_RESP_SEQ)
    /* c8 ignore next 3 — guarded by sabQueue serialisation */
    if (slot.sabRespSeq !== expectedResp) {
      throw new Error('coraza: pool worker SAB sequence mismatch')
    }

    const rc = Atomics.load(ctrlI32, CTRL_RESP_RC)
    if (rc === -1) {
      const errLen = Atomics.load(ctrlI32, CTRL_RESP_ERR_LEN)
      const msg = errLen > 0
        ? new TextDecoder().decode(dataU8.subarray(0, errLen))
        : 'worker error'
      throw new Error(msg)
    }
    if (rc === 1) {
      const intLen = Atomics.load(ctrlI32, CTRL_RESP_INT_LEN)
      if (intLen > 0) {
        try {
          this.#cachedInterruption = JSON.parse(
            new TextDecoder().decode(dataU8.subarray(0, intLen)),
          ) as Interruption
        } catch {
          this.#cachedInterruption = undefined
        }
      }
    }
    return rc === 1
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
    if (this.#cachedInterruption !== undefined) return this.#cachedInterruption
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

  async #procFallback(
    req: RequestInfo,
    body: Uint8Array | string | undefined,
  ): Promise<boolean> {
    const { interrupted } = await this.#proc('requestBundle', { req, body })
    return interrupted
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

function spawnSlot(logger: Logger): WorkerSlot {
  const workerUrl = new URL('./pool-worker.js', import.meta.url)
  const worker = new Worker(fileURLToPath(workerUrl), {
    // Don't inherit the parent's loader args (e.g. --import tsx) — the worker
    // runs the pre-compiled pool-worker.js and doesn't need the TS loader.
    execArgv: [],
  })
  const pending = new Map<number, Pending>()
  const sabData = new SharedArrayBuffer(DATA_SAB_BYTES)
  const sabCtrl = new SharedArrayBuffer(CTRL_I32_SIZE * 4)
  const slot: WorkerSlot = {
    worker,
    pending,
    busy: 0,
    ready: new Promise<void>((resolve, reject) => {
      worker.once('online', () => resolve())
      worker.once('error', (e) => reject(e))
    }),
    sabData,
    sabCtrl,
    sabDataU8: new Uint8Array(sabData),
    sabCtrlI32: new Int32Array(sabCtrl),
    sabReqSeq: 0,
    sabRespSeq: 0,
    sabHeaderBuf: { current: new Uint8Array(8192) },
    sabQueue: Promise.resolve(),
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

// Thin wrapper over Atomics.waitAsync that also implements a timeout via
// Promise.race. Atomics.waitAsync's native timeout argument is not universally
// honoured on all runtimes we target, so we race a setTimeout to guarantee
// the caller never awaits forever. Synchronously-resolved waits (the value
// already changed) short-circuit to avoid an event-loop round trip.
function waitAsync(
  i32: Int32Array,
  index: number,
  value: number,
  timeoutMs: number,
): { async: false; value: 'ok' | 'not-equal' | 'timed-out' } | {
  async: true
  value: Promise<'ok' | 'not-equal' | 'timed-out'>
} {
  const res = Atomics.waitAsync(i32, index, value) as
    | { async: false; value: 'not-equal' | 'ok' | 'timed-out' }
    | { async: true; value: Promise<'ok' | 'timed-out'> }
  if (!res.async) return res
  let t: NodeJS.Timeout | undefined
  const timer = new Promise<'timed-out'>((resolve) => {
    t = setTimeout(() => resolve('timed-out'), timeoutMs)
  })
  const wrapped = Promise.race([res.value, timer]).finally(() => {
    if (t) clearTimeout(t)
  }) as Promise<'ok' | 'timed-out'>
  return { async: true, value: wrapped }
}

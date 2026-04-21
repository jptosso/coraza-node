// Worker-thread entry point for @coraza/core's WAFPool.
//
// Two input channels:
//   - parentPort messages (structured clone) for control + rare ops:
//     init, newTx, close, reset, shutdown, predicates, matched-rules,
//     and the fallback slow path for oversize request bundles.
//   - SharedArrayBuffer + Atomics.waitAsync for the hot path:
//     processRequestBundle calls. Main thread writes the encoded bundle
//     into the shared data region, bumps the control-word sequence, and
//     we decode directly from the shared region. Saves the structured
//     clone + MessagePort hop — the single biggest pool-mode overhead.
//
// Wire format (postMessage): every message has a numeric `reqId`; replies
// echo the id so the main thread can resolve the matching promise.

import { parentPort, workerData } from 'node:worker_threads'
import { createWAF, type WAF } from './waf.js'
import { Transaction } from './transaction.js'
import type {
  Interruption,
  MatchedRule,
  RequestInfo,
  ResponseInfo,
  WAFConfig,
} from './types.js'

if (!parentPort) {
  throw new Error('@coraza/core pool-worker: must run inside a worker_thread')
}

// Keep in lockstep with src/pool.ts.
const CTRL_REQ_SEQ = 0
const CTRL_REQ_LEN = 1
const CTRL_REQ_TX_ID = 2
const CTRL_RESP_SEQ = 3
const CTRL_RESP_RC = 4
const CTRL_RESP_INT_LEN = 5
const CTRL_RESP_ERR_LEN = 6

type InitMsg = {
  reqId: number
  type: 'init'
  config: WAFConfig
  sabData?: SharedArrayBuffer
  sabCtrl?: SharedArrayBuffer
}
type NewTxMsg = { reqId: number; type: 'newTx' }
type ProcMsg = {
  reqId: number
  type: 'proc'
  txId: number
  op: 'requestBundle' | 'response' | 'responseBody' | 'logging'
  args?: unknown
}
type PredMsg = {
  reqId: number
  type: 'pred'
  txId: number
  which: 'ruleEngineOff' | 'reqBodyAccessible' | 'respBodyAccessible' | 'respBodyProcessable'
}
type GetMsg = {
  reqId: number
  type: 'get'
  txId: number
  which: 'interruption' | 'matchedRules'
}
type ResetMsg = { reqId: number; type: 'reset'; txId: number }
type CloseMsg = { reqId: number; type: 'close'; txId: number }
type ShutdownMsg = { reqId: number; type: 'shutdown' }
type Msg = InitMsg | NewTxMsg | ProcMsg | PredMsg | GetMsg | ResetMsg | CloseMsg | ShutdownMsg

let waf: WAF | null = null
const txs = new Map<number, Transaction>()
let nextTxId = 0
let sabCtrl: Int32Array | null = null
let sabDataU8: Uint8Array | null = null
let sabLastSeq = 0
let sabShutdown = false
const encoder = new TextEncoder()

parentPort.on('message', async (msg: Msg) => {
  try {
    switch (msg.type) {
      case 'init':
        waf = await createWAF(msg.config)
        if (msg.sabData && msg.sabCtrl) {
          sabDataU8 = new Uint8Array(msg.sabData)
          sabCtrl = new Int32Array(msg.sabCtrl)
          // Kick off the Atomics polling loop. waitAsync keeps the event
          // loop unblocked so parentPort messages still get serviced.
          void sabLoop()
        }
        parentPort!.postMessage({ reqId: msg.reqId, ok: true })
        break

      case 'newTx': {
        if (!waf) throw new Error('worker not initialized')
        const id = ++nextTxId
        txs.set(id, waf.newTransaction())
        parentPort!.postMessage({ reqId: msg.reqId, ok: true, txId: id })
        break
      }

      case 'proc': {
        const tx = txs.get(msg.txId)
        if (!tx) throw new Error(`unknown tx ${msg.txId}`)
        let interrupted: boolean | void = false
        switch (msg.op) {
          case 'requestBundle': {
            const a = msg.args as { req: RequestInfo; body: Uint8Array | string | undefined }
            interrupted = tx.processRequestBundle(a.req, a.body)
            break
          }
          case 'response':
            interrupted = tx.processResponse(msg.args as ResponseInfo)
            break
          case 'responseBody':
            interrupted = tx.processResponseBody(msg.args as Uint8Array | string | undefined)
            break
          case 'logging':
            tx.processLogging()
            break
        }
        parentPort!.postMessage({ reqId: msg.reqId, ok: true, interrupted: Boolean(interrupted) })
        break
      }

      case 'pred': {
        const tx = txs.get(msg.txId)
        if (!tx) throw new Error(`unknown tx ${msg.txId}`)
        let val = false
        switch (msg.which) {
          case 'ruleEngineOff':
            val = tx.isRuleEngineOff()
            break
          case 'reqBodyAccessible':
            val = tx.isRequestBodyAccessible()
            break
          case 'respBodyAccessible':
            val = tx.isResponseBodyAccessible()
            break
          case 'respBodyProcessable':
            val = tx.isResponseBodyProcessable()
            break
        }
        parentPort!.postMessage({ reqId: msg.reqId, ok: true, value: val })
        break
      }

      case 'get': {
        const tx = txs.get(msg.txId)
        if (!tx) throw new Error(`unknown tx ${msg.txId}`)
        const val: Interruption | MatchedRule[] | null =
          msg.which === 'interruption' ? tx.interruption() : tx.matchedRules()
        parentPort!.postMessage({ reqId: msg.reqId, ok: true, value: val })
        break
      }

      case 'reset': {
        const tx = txs.get(msg.txId)
        if (!tx) throw new Error(`unknown tx ${msg.txId}`)
        tx.reset()
        parentPort!.postMessage({ reqId: msg.reqId, ok: true })
        break
      }

      case 'close': {
        const tx = txs.get(msg.txId)
        if (tx) {
          try {
            tx.processLogging()
          } finally {
            tx.close()
            txs.delete(msg.txId)
          }
        }
        parentPort!.postMessage({ reqId: msg.reqId, ok: true })
        break
      }

      case 'shutdown':
        sabShutdown = true
        if (sabCtrl) {
          // Wake any parked waitAsync promise so the loop can exit cleanly.
          Atomics.notify(sabCtrl, CTRL_REQ_SEQ, 1)
        }
        for (const [id, tx] of txs) {
          try {
            tx.close()
          } catch { /* ignore */ }
          txs.delete(id)
        }
        waf?.destroy()
        parentPort!.postMessage({ reqId: msg.reqId, ok: true })
        parentPort!.close()
        break
    }
  } catch (err) {
    parentPort!.postMessage({
      reqId: msg.reqId,
      ok: false,
      error: (err as Error).message,
    })
  }
})

async function sabLoop(): Promise<void> {
  /* c8 ignore next — guarded by init path */
  if (!sabCtrl || !sabDataU8) return
  while (!sabShutdown) {
    const res = Atomics.waitAsync(sabCtrl, CTRL_REQ_SEQ, sabLastSeq)
    if (res.async) {
      await res.value
    }
    if (sabShutdown) break
    const seq = Atomics.load(sabCtrl, CTRL_REQ_SEQ)
    // Spurious wake / no new request: re-park.
    if (seq === sabLastSeq) continue
    sabLastSeq = seq

    const len = Atomics.load(sabCtrl, CTRL_REQ_LEN)
    const txId = Atomics.load(sabCtrl, CTRL_REQ_TX_ID)
    let rc = 0
    let errLen = 0
    let intLen = 0
    try {
      const tx = txs.get(txId)
      if (!tx) throw new Error(`coraza: SAB tx ${txId} missing`)
      // Snapshot the bundle bytes into a plain Uint8Array. The WAF path
      // copies into WASM memory internally (host_malloc + writeAt), so
      // the shared region can be safely reused after this call returns.
      // Skipping the copy and handing the SAB view straight to the ABI
      // is fine in principle, but a subsequent write from the main thread
      // during the ABI call could corrupt the read — the copy is cheap
      // insurance against that race, which the main side's sabQueue
      // serialisation should prevent but must never depend on.
      const bundleCopy = new Uint8Array(len)
      bundleCopy.set(sabDataU8.subarray(0, len))
      const interrupted = tx.processEncodedRequestBundle(bundleCopy)
      rc = interrupted ? 1 : 0
      // Write the serialised interruption JSON back into the data region
      // so the main thread can pick it up without a second call. Small
      // bodies (< ~1 KiB) fit easily; oversize interruption payloads get
      // fetched via the postMessage `get` fallback.
      if (interrupted) {
        const it = tx.interruption()
        if (it) {
          const json = JSON.stringify(it)
          const bytes = encoder.encode(json)
          /* c8 ignore next 7 — interruption JSON fits comfortably in scratch */
          if (bytes.length <= sabDataU8.length) {
            sabDataU8.set(bytes, 0)
            intLen = bytes.length
          } else {
            intLen = 0
          }
        }
      }
    } catch (err) {
      rc = -1
      const msg = (err as Error).message ?? 'worker error'
      const bytes = encoder.encode(msg)
      const cap = Math.min(bytes.length, sabDataU8.length)
      sabDataU8.set(bytes.subarray(0, cap), 0)
      errLen = cap
    }

    Atomics.store(sabCtrl, CTRL_RESP_RC, rc)
    Atomics.store(sabCtrl, CTRL_RESP_INT_LEN, intLen)
    Atomics.store(sabCtrl, CTRL_RESP_ERR_LEN, errLen)
    const respSeq = Atomics.add(sabCtrl, CTRL_RESP_SEQ, 1) + 1
    void respSeq
    Atomics.notify(sabCtrl, CTRL_RESP_SEQ, 1)
  }
}

// Surface unhandled rejections to the main thread rather than killing the worker.
process.on('unhandledRejection', (err) => {
  parentPort!.postMessage({
    reqId: -1,
    ok: false,
    error: `unhandledRejection: ${(err as Error)?.message ?? String(err)}`,
  })
})

// workerData is only referenced to allow future configuration plumbing.
void workerData

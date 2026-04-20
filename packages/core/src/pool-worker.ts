// Worker-thread entry point for @coraza/core's WAFPool.
//
// Receives commands from the main thread over parentPort and drives a
// single WAF instance + its transactions inside this worker. Keeping one
// WAF per worker lets us parallelize WAF-heavy workloads across CPU cores
// without any shared state.
//
// Wire format: every message has a numeric `reqId`. Replies echo the id
// so the main thread can resolve the matching promise.

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

type InitMsg = { reqId: number; type: 'init'; config: WAFConfig }
type NewTxMsg = { reqId: number; type: 'newTx' }
type ProcMsg = {
  reqId: number
  type: 'proc'
  txId: number
  op: 'request' | 'requestBundle' | 'requestBody' | 'response' | 'responseBody' | 'logging'
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
type CloseMsg = { reqId: number; type: 'close'; txId: number }
type ShutdownMsg = { reqId: number; type: 'shutdown' }
type Msg = InitMsg | NewTxMsg | ProcMsg | PredMsg | GetMsg | CloseMsg | ShutdownMsg

let waf: WAF | null = null
const txs = new Map<number, Transaction>()
let nextTxId = 0

parentPort.on('message', async (msg: Msg) => {
  try {
    switch (msg.type) {
      case 'init':
        waf = await createWAF(msg.config)
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
          case 'request':
            interrupted = tx.processRequest(msg.args as RequestInfo)
            break
          case 'requestBundle': {
            const a = msg.args as { req: RequestInfo; body: Uint8Array | string | undefined }
            interrupted = tx.processRequestBundle(a.req, a.body)
            break
          }
          case 'requestBody':
            interrupted = tx.processRequestBody(msg.args as Uint8Array | string | undefined)
            break
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

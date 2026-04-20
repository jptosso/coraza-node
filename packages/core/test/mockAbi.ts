// Faithful in-memory stand-in for the Coraza WASM exports. Lets the core
// package be unit-tested without a real .wasm binary. The mock tracks
// allocations, remembers inputs, and returns caller-controlled verdicts.

import type { CorazaExports } from '../src/abi.js'

export interface MockState {
  memBytes: number
  allocs: Map<number, number> // ptr -> len
  wafs: Set<number>
  txs: Map<number, TxState>
  nextWaf: number
  nextTx: number
  lastError: string
  scratch: { ptr: number; cap: number }
  abiVersionValue: number
  ruleEngineOff: boolean
  reqBodyAccessible: boolean
  respBodyAccessible: boolean
  respBodyProcessable: boolean
}

export interface TxState {
  wafId: number
  interrupt?: { ruleId: number; action: string; status: number; data: string }
  matchedRules: { id: number; severity: number; message: string }[]
  closed: boolean
  lastBody?: Uint8Array
  headers: [string, string][]
  responseHeaders: [string, string][]
  uri?: { method: string; uri: string; proto: string }
  conn?: { addr: string; cport: number; sport: number }
  loggingCalls: number
}

export interface MockOptions {
  /** When set, waf_create returns -1 and last_error reports this. */
  failWafCreate?: string
  /** Predicate: given tx state, return an interruption to raise. */
  onHeaders?: (tx: TxState) => TxState['interrupt'] | undefined
  onBody?: (tx: TxState) => TxState['interrupt'] | undefined
  onResponseHeaders?: (tx: TxState) => TxState['interrupt'] | undefined
  onResponseBody?: (tx: TxState) => TxState['interrupt'] | undefined
  /** Force abi_version to return a specific packed value. */
  abiVersion?: number
  /** Force malloc to return 0 (OOM) after N successful calls. */
  mallocFailAfter?: number
  /** Throw from last_error when called (for edge case tests). */
  errorFromCall?: 'waf_create' | 'tx_create' | 'tx_process_uri' | 'tx_process_request_headers'
}

const encoder = new TextEncoder()

export function createMock(opts: MockOptions = {}): {
  exports: CorazaExports
  state: MockState
} {
  const CAP = 4096
  const buf = new ArrayBuffer(64 * 1024)
  const memory = { buffer: buf } as WebAssembly.Memory
  const mem = () => new Uint8Array(memory.buffer)

  const state: MockState = {
    memBytes: CAP,
    allocs: new Map(),
    wafs: new Set(),
    txs: new Map(),
    nextWaf: 0,
    nextTx: 0,
    lastError: '',
    scratch: { ptr: 0, cap: CAP },
    abiVersionValue: opts.abiVersion ?? (1 << 16),
    ruleEngineOff: false,
    reqBodyAccessible: true,
    respBodyAccessible: true,
    respBodyProcessable: true,
  }

  let bumpPtr = CAP // scratch lives at [0, CAP); malloc bumps upward
  let mallocCalls = 0

  const exports: CorazaExports = {
    memory,

    abi_version: () => state.abiVersionValue,

    last_error: () => {
      if (!state.lastError) return 0n
      const bytes = encoder.encode(state.lastError)
      mem().set(bytes, 0)
      state.lastError = ''
      return pack(0, bytes.length)
    },

    host_malloc: (size) => {
      mallocCalls++
      if (opts.mallocFailAfter !== undefined && mallocCalls > opts.mallocFailAfter) return 0
      if (size <= 0) return 0
      const ptr = bumpPtr
      bumpPtr += size
      state.allocs.set(ptr, size)
      return ptr
    },
    host_free: (ptr) => {
      state.allocs.delete(ptr)
    },
    scratch_ptr: () => state.scratch.ptr,
    scratch_cap: () => state.scratch.cap,

    waf_create: (cfgPtr, cfgLen) => {
      if (opts.failWafCreate) {
        state.lastError = opts.failWafCreate
        return -1
      }
      // touch inputs so tests can assert on them
      mem().slice(cfgPtr, cfgPtr + cfgLen)
      state.nextWaf++
      state.wafs.add(state.nextWaf)
      return state.nextWaf
    },
    waf_destroy: (id) => {
      state.wafs.delete(id)
    },

    tx_create: (wafId) => {
      if (!state.wafs.has(wafId)) {
        state.lastError = 'unknown waf'
        return -1
      }
      state.nextTx++
      state.txs.set(state.nextTx, {
        wafId,
        matchedRules: [],
        headers: [],
        responseHeaders: [],
        closed: false,
        loggingCalls: 0,
      })
      return state.nextTx
    },
    tx_destroy: (id) => {
      const t = state.txs.get(id)
      if (!t) return
      t.closed = true
      state.txs.delete(id)
    },
    tx_has_interrupt: (id) => {
      const t = state.txs.get(id)
      return t?.interrupt ? 1 : 0
    },
    tx_is_rule_engine_off: (id) => {
      const t = state.txs.get(id)
      if (!t) return 1
      return state.ruleEngineOff ? 1 : 0
    },
    tx_is_request_body_accessible: (id) => {
      const t = state.txs.get(id)
      if (!t) return 0
      return state.reqBodyAccessible ? 1 : 0
    },
    tx_is_response_body_accessible: (id) => {
      const t = state.txs.get(id)
      if (!t) return 0
      return state.respBodyAccessible ? 1 : 0
    },
    tx_is_response_body_processable: (id) => {
      const t = state.txs.get(id)
      if (!t) return 0
      return state.respBodyProcessable ? 1 : 0
    },

    tx_process_connection: (id, addrPtr, addrLen, cport, sport) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      const addr = new TextDecoder().decode(mem().subarray(addrPtr, addrPtr + addrLen))
      t.conn = { addr, cport, sport }
      return 0
    },
    tx_process_uri: (id, methodPtr, methodLen, uriPtr, uriLen, protoPtr, protoLen) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      const dec = new TextDecoder()
      t.uri = {
        method: dec.decode(mem().subarray(methodPtr, methodPtr + methodLen)),
        uri: dec.decode(mem().subarray(uriPtr, uriPtr + uriLen)),
        proto: dec.decode(mem().subarray(protoPtr, protoPtr + protoLen)),
      }
      return 0
    },
    tx_process_request_headers: (id, pktPtr, pktLen) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      t.headers = decodePacket(mem(), pktPtr, pktLen)
      const it = opts.onHeaders?.(t)
      if (it) {
        t.interrupt = it
        return 1
      }
      return 0
    },
    tx_process_request_body: (id, ptr, len) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      t.lastBody = mem().slice(ptr, ptr + len)
      const it = opts.onBody?.(t)
      if (it) {
        t.interrupt = it
        return 1
      }
      return 0
    },
    tx_process_request_bundle: (id, ptr, len) => {
      // Minimal bundle decoder — mirror the wire format in wasm/bundle.go.
      // Only decodes enough to populate the same mock state fields that
      // the individual process_* calls would set, then applies the
      // caller's onHeaders/onBody predicates (checked in wire order).
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      const m = mem()
      const view = new DataView(m.buffer, m.byteOffset + ptr, len)
      let o = 0
      const addrLen = view.getUint16(o, true); o += 2
      const addr = new TextDecoder().decode(m.subarray(ptr + o, ptr + o + addrLen))
      o += addrLen
      const cport = view.getUint16(o, true); o += 2
      const sport = view.getUint16(o, true); o += 2
      const methodLen = m[ptr + o]!; o += 1
      const method = new TextDecoder().decode(m.subarray(ptr + o, ptr + o + methodLen))
      o += methodLen
      const protoLen = m[ptr + o]!; o += 1
      const proto = new TextDecoder().decode(m.subarray(ptr + o, ptr + o + protoLen))
      o += protoLen
      const urlLen = view.getUint32(o, true); o += 4
      const uri = new TextDecoder().decode(m.subarray(ptr + o, ptr + o + urlLen))
      o += urlLen
      const hdrLen = view.getUint32(o, true); o += 4
      t.headers = decodePacket(m, ptr + o, hdrLen)
      o += hdrLen
      const bodyLen = view.getUint32(o, true); o += 4
      t.lastBody = m.slice(ptr + o, ptr + o + bodyLen)

      t.conn = { addr, cport, sport }
      t.uri = { method, uri, proto }

      // Phase-1 header predicate first (matches real Coraza order).
      const hdrIt = opts.onHeaders?.(t)
      if (hdrIt) {
        t.interrupt = hdrIt
        return 1
      }
      // Phase-2 body predicate second.
      const bodyIt = opts.onBody?.(t)
      if (bodyIt) {
        t.interrupt = bodyIt
        return 1
      }
      return 0
    },
    tx_append_request_body: (id, ptr, len) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      const chunk = mem().slice(ptr, ptr + len)
      t.lastBody = concat(t.lastBody, chunk)
      return 0
    },
    tx_process_request_body_finish: (id) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      const it = opts.onBody?.(t)
      if (it) {
        t.interrupt = it
        return 1
      }
      return 0
    },
    tx_process_response_headers: (id, status, pktPtr, pktLen /* proto omitted intentionally */) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      t.responseHeaders = decodePacket(mem(), pktPtr, pktLen)
      const it = opts.onResponseHeaders?.(t)
      if (it) {
        t.interrupt = it
        return 1
      }
      void status
      return 0
    },
    tx_process_response_body: (id, ptr, len) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      t.lastBody = mem().slice(ptr, ptr + len)
      const it = opts.onResponseBody?.(t)
      if (it) {
        t.interrupt = it
        return 1
      }
      return 0
    },
    tx_append_response_body: (id, ptr, len) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      const chunk = mem().slice(ptr, ptr + len)
      t.lastBody = concat(t.lastBody, chunk)
      return 0
    },
    tx_process_response_body_finish: (id) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      const it = opts.onResponseBody?.(t)
      if (it) {
        t.interrupt = it
        return 1
      }
      return 0
    },
    tx_process_logging: (id) => {
      const t = state.txs.get(id)
      if (!t) {
        state.lastError = 'unknown tx'
        return -1
      }
      t.loggingCalls++
      return 0
    },

    tx_get_interrupt: (id) => {
      const t = state.txs.get(id)
      if (!t?.interrupt) return 0n
      const json = JSON.stringify(t.interrupt)
      const bytes = encoder.encode(json)
      mem().set(bytes, 0)
      return pack(0, bytes.length)
    },
    tx_get_matched_rules: (id) => {
      const t = state.txs.get(id)
      if (!t || t.matchedRules.length === 0) return 0n
      const json = JSON.stringify(t.matchedRules)
      const bytes = encoder.encode(json)
      mem().set(bytes, 0)
      return pack(0, bytes.length)
    },
  }

  return { exports, state }
}

function pack(ptr: number, len: number): bigint {
  return (BigInt(ptr) << 32n) | BigInt(len)
}

function decodePacket(mem: Uint8Array, ptr: number, len: number): [string, string][] {
  if (len === 0) return []
  const view = new DataView(mem.buffer, mem.byteOffset + ptr, len)
  const dec = new TextDecoder()
  const count = view.getUint32(0, true)
  let off = 4
  const out: [string, string][] = []
  for (let i = 0; i < count; i++) {
    const nl = view.getUint32(off, true)
    off += 4
    const name = dec.decode(new Uint8Array(mem.buffer, mem.byteOffset + ptr + off, nl))
    off += nl
    const vl = view.getUint32(off, true)
    off += 4
    const value = dec.decode(new Uint8Array(mem.buffer, mem.byteOffset + ptr + off, vl))
    off += vl
    out.push([name, value])
  }
  return out
}

function concat(a: Uint8Array | undefined, b: Uint8Array): Uint8Array {
  if (!a || a.length === 0) return b
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

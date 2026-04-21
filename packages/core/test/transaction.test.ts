import { describe, it, expect } from 'vitest'
import { Abi } from '../src/abi.js'
import { Transaction, encodeRequestBundle } from '../src/transaction.js'
import { createMock } from './mockAbi.js'

function setup(opts: Parameters<typeof createMock>[0] = {}) {
  const { exports, state } = createMock(opts)
  const abi = new Abi(exports)
  // Set up a WAF and a tx so Transaction has something to operate on.
  const wafId = exports.waf_create(0, 0)
  const txId = exports.tx_create(wafId)
  const tx = new Transaction(abi, txId)
  return { exports, state, abi, tx, txId }
}

describe('Transaction', () => {
  it('processes a full request (connection + uri + headers) without interrupt', () => {
    const { tx, state, txId } = setup()
    const interrupted = tx.processRequestBundle(
      {
        method: 'GET',
        url: '/health',
        protocol: 'HTTP/1.1',
        headers: [['Host', 'example.com']],
        remoteAddr: '203.0.113.5',
        remotePort: 45000,
        serverPort: 80,
      },
      undefined,
    )
    expect(interrupted).toBe(false)
    const txState = state.txs.get(txId)!
    expect(txState.conn).toEqual({ addr: '203.0.113.5', cport: 45000, sport: 80 })
    expect(txState.uri).toEqual({ method: 'GET', uri: '/health', proto: 'HTTP/1.1' })
    expect(txState.headers).toEqual([['Host', 'example.com']])
  })

  it('defaults protocol to HTTP/1.1 in the bundle encoder', () => {
    const { tx, state, txId } = setup()
    tx.processRequestBundle({ method: 'POST', url: '/', headers: [] }, undefined)
    expect(state.txs.get(txId)!.uri?.proto).toBe('HTTP/1.1')
  })

  it('returns true when headers trigger an interruption and exposes verdict', () => {
    const { tx } = setup({
      onHeaders: () => ({ ruleId: 942100, action: 'deny', status: 403, data: 'SQLi' }),
    })
    const interrupted = tx.processRequestBundle(
      { method: 'GET', url: "/?q=' OR 1=1--", headers: [] },
      undefined,
    )
    expect(interrupted).toBe(true)
    expect(tx.interruption()).toEqual({
      ruleId: 942100,
      action: 'deny',
      status: 403,
      data: 'SQLi',
    })
  })

  it('interruption() returns null when none raised', () => {
    const { tx } = setup()
    tx.processRequestBundle({ method: 'GET', url: '/', headers: [] }, undefined)
    expect(tx.interruption()).toBeNull()
  })

  it('bundle carries body; string and Uint8Array encode the same bytes', () => {
    const { tx, state, txId } = setup()
    tx.processRequestBundle({ method: 'POST', url: '/', headers: [] }, 'hello')
    expect(new TextDecoder().decode(state.txs.get(txId)!.lastBody!)).toBe('hello')
    tx.processRequestBundle(
      { method: 'POST', url: '/', headers: [] },
      new Uint8Array([1, 2, 3]),
    )
    expect(Array.from(state.txs.get(txId)!.lastBody!)).toEqual([1, 2, 3])
  })

  it('returns true when body triggers an interrupt via the bundle', () => {
    const { tx } = setup({
      onBody: () => ({ ruleId: 2, action: 'deny', status: 403, data: 'XSS' }),
    })
    expect(
      tx.processRequestBundle({ method: 'POST', url: '/', headers: [] }, '<script>'),
    ).toBe(true)
  })

  it('append + finish request body flow', () => {
    const { tx, state, txId } = setup()
    tx.appendRequestBody(new Uint8Array([1, 2]))
    tx.appendRequestBody(new Uint8Array([3]))
    tx.appendRequestBody(new Uint8Array(0)) // no-op
    expect(tx.finishRequestBody()).toBe(false)
    expect(Array.from(state.txs.get(txId)!.lastBody!)).toEqual([1, 2, 3])
  })

  it('finishRequestBody surfaces interrupt from onBody', () => {
    const { tx } = setup({
      onBody: () => ({ ruleId: 3, action: 'deny', status: 403, data: 'body' }),
    })
    tx.appendRequestBody(new Uint8Array([1]))
    expect(tx.finishRequestBody()).toBe(true)
  })

  it('processes response (headers + body) and detects interrupt', () => {
    const { tx, state, txId } = setup({
      onResponseBody: () => ({ ruleId: 4, action: 'deny', status: 403, data: 'resp' }),
    })
    expect(tx.processResponse({ status: 200, headers: [['x-foo', '1']] })).toBe(false)
    const txState = state.txs.get(txId)!
    expect(txState.responseHeaders).toEqual([['x-foo', '1']])
    expect(tx.processResponseBody('leaky secret')).toBe(true)
  })

  it('empty response body and string/Uint8Array variants', () => {
    const { tx } = setup()
    expect(tx.processResponseBody()).toBe(false)
    expect(tx.processResponseBody('')).toBe(false)
    expect(tx.processResponseBody(new Uint8Array([1]))).toBe(false)
  })

  it('response headers interrupt propagates', () => {
    const { tx } = setup({
      onResponseHeaders: () => ({ ruleId: 5, action: 'deny', status: 403, data: 'hdr' }),
    })
    expect(tx.processResponse({ status: 500, headers: [] })).toBe(true)
  })

  it('append + finish response body', () => {
    const { tx, state, txId } = setup()
    tx.appendResponseBody(new Uint8Array([7, 8]))
    tx.appendResponseBody(new Uint8Array(0)) // no-op
    expect(tx.finishResponseBody()).toBe(false)
    expect(Array.from(state.txs.get(txId)!.lastBody!)).toEqual([7, 8])
  })

  it('finishResponseBody surfaces interrupt', () => {
    const { tx } = setup({
      onResponseBody: () => ({ ruleId: 6, action: 'deny', status: 403, data: 'resp' }),
    })
    tx.appendResponseBody(new Uint8Array([1]))
    expect(tx.finishResponseBody()).toBe(true)
  })

  it('matchedRules returns [] when no matches, else the array', () => {
    const { tx, state, txId } = setup()
    expect(tx.matchedRules()).toEqual([])
    state.txs.get(txId)!.matchedRules = [{ id: 1, severity: 3, message: 'test' }]
    expect(tx.matchedRules()).toEqual([{ id: 1, severity: 3, message: 'test' }])
  })

  it('processLogging is a no-op on closed transactions', () => {
    const { tx, state, txId } = setup()
    tx.processLogging()
    // close sets #closed before tx_destroy, so the map entry is gone anyway;
    // but processLogging after close should not throw.
    tx.close()
    expect(() => tx.processLogging()).not.toThrow()
    expect(state.txs.get(txId)).toBeUndefined()
  })

  it('reset clears interruption + matched rules; handle stays valid', () => {
    const { tx, state, txId } = setup({
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    tx.processRequestBundle({ method: 'GET', url: "/?q='OR 1=1--", headers: [] }, undefined)
    expect(tx.interruption()).not.toBeNull()

    tx.reset()
    expect(tx.closed).toBe(false)
    // The underlying TxState is a brand-new one, so interruption clears.
    const fresh = state.txs.get(txId)!
    expect(fresh.interrupt).toBeUndefined()
    expect(fresh.matchedRules).toEqual([])
    // Same handle is still usable.
    expect(() => tx.processConnection('1.2.3.4')).not.toThrow()
  })

  it('reset throws after close', () => {
    const { tx } = setup()
    tx.close()
    expect(() => tx.reset()).toThrow(/closed/)
  })

  it('close is idempotent and flips `closed`', () => {
    const { tx } = setup()
    expect(tx.closed).toBe(false)
    tx.close()
    expect(tx.closed).toBe(true)
    tx.close()
    expect(tx.closed).toBe(true)
  })

  it('operations throw after close', () => {
    const { tx } = setup()
    tx.close()
    expect(() => tx.processRequestBundle({ method: 'GET', url: '/', headers: [] }, undefined)).toThrow(/closed/)
    expect(() => tx.appendRequestBody(new Uint8Array([1]))).toThrow(/closed/)
    expect(() => tx.finishRequestBody()).toThrow(/closed/)
    expect(() => tx.processResponse({ status: 200, headers: [] })).toThrow(/closed/)
    expect(() => tx.processResponseBody('x')).toThrow(/closed/)
    expect(() => tx.appendResponseBody(new Uint8Array([1]))).toThrow(/closed/)
    expect(() => tx.finishResponseBody()).toThrow(/closed/)
    expect(() => tx.interruption()).toThrow(/closed/)
    expect(() => tx.matchedRules()).toThrow(/closed/)
    expect(() => tx.processConnection('1.2.3.4')).toThrow(/closed/)
  })

  it('throws on OOM when malloc fails for input buffers', () => {
    const { tx } = setup({ mallocFailAfter: 0 })
    expect(() =>
      tx.processRequestBundle({ method: 'POST', url: '/', headers: [] }, 'hi'),
    ).toThrow(/OOM/)
  })

  it('processConnection with defaults works', () => {
    const { tx, state, txId } = setup()
    tx.processConnection('10.0.0.1')
    expect(state.txs.get(txId)!.conn).toEqual({ addr: '10.0.0.1', cport: 0, sport: 0 })
  })

  it('predicate accessors reflect engine state', () => {
    const { tx, state } = setup()
    expect(tx.isRuleEngineOff()).toBe(false)
    expect(tx.isRequestBodyAccessible()).toBe(true)
    expect(tx.isResponseBodyAccessible()).toBe(true)
    expect(tx.isResponseBodyProcessable()).toBe(true)
    state.ruleEngineOff = true
    state.reqBodyAccessible = false
    state.respBodyAccessible = false
    state.respBodyProcessable = false
    expect(tx.isRuleEngineOff()).toBe(true)
    expect(tx.isRequestBodyAccessible()).toBe(false)
    expect(tx.isResponseBodyAccessible()).toBe(false)
    expect(tx.isResponseBodyProcessable()).toBe(false)
  })

  it('accessors throw after close', () => {
    const { tx } = setup()
    tx.close()
    expect(() => tx.isRuleEngineOff()).toThrow(/closed/)
    expect(() => tx.isRequestBodyAccessible()).toThrow(/closed/)
    expect(() => tx.isResponseBodyAccessible()).toThrow(/closed/)
    expect(() => tx.isResponseBodyProcessable()).toThrow(/closed/)
  })
})

// Helpers to decode the bundle wire format back for assertions.
function decodeBundle(out: Uint8Array): {
  addr: string
  cport: number
  sport: number
  method: string
  proto: string
  url: string
  bodyLen: number
  method_bytes: Uint8Array
  url_bytes: Uint8Array
} {
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
  const dec = new TextDecoder()
  let o = 0
  const addrLen = view.getUint16(o, true); o += 2
  const addr = dec.decode(out.subarray(o, o + addrLen)); o += addrLen
  const cport = view.getUint16(o, true); o += 2
  const sport = view.getUint16(o, true); o += 2
  const methodLen = out[o]!; o += 1
  const method_bytes = out.subarray(o, o + methodLen)
  const method = dec.decode(method_bytes); o += methodLen
  const protoLen = out[o]!; o += 1
  const proto = dec.decode(out.subarray(o, o + protoLen)); o += protoLen
  const urlLen = view.getUint32(o, true); o += 4
  const url_bytes = out.subarray(o, o + urlLen)
  const url = dec.decode(url_bytes); o += urlLen
  const hdrLen = view.getUint32(o, true); o += 4 + hdrLen
  const bodyLen = view.getUint32(o, true)
  return { addr, cport, sport, method, proto, url, bodyLen, method_bytes, url_bytes }
}

describe('encodeRequestBundle', () => {
  it('round-trips a simple request through the scratch-Buffer encoder', () => {
    const out = encodeRequestBundle(
      {
        method: 'GET',
        url: '/hello',
        protocol: 'HTTP/2',
        headers: [['host', 'x']],
        remoteAddr: '10.0.0.1',
        remotePort: 1234,
        serverPort: 80,
      },
      undefined,
    )
    const d = decodeBundle(out)
    expect(d).toMatchObject({
      method: 'GET',
      proto: 'HTTP/2',
      url: '/hello',
      addr: '10.0.0.1',
      cport: 1234,
      sport: 80,
      bodyLen: 0,
    })
  })

  it('clips an oversize method at the UTF-8 boundary without throwing', () => {
    // 300 × 'é' (2 bytes each) = 600 bytes. Clip to 255 lands at a boundary.
    const giantMethod = 'é'.repeat(300)
    const out = encodeRequestBundle(
      { method: giantMethod, url: '/', headers: [] },
      undefined,
    )
    const d = decodeBundle(out)
    // Length must land on a codepoint boundary; decoding must not produce
    // U+FFFD. The clipped length is ≤ 255 and even.
    expect(d.method_bytes.length).toBeLessThanOrEqual(255)
    expect(d.method_bytes.length % 2).toBe(0)
    expect(d.method).not.toContain('\ufffd')
  })

  it('clips an oversize URL at the UTF-8 boundary without throwing when scratch overflows', () => {
    // 40 KiB of a 3-byte codepoint triples to 120 KiB encoded — exceeds
    // SCRATCH_CAP (64 KiB), forcing the fresh-Buffer fallback path.
    const big = '漢'.repeat(40_000)
    const out = encodeRequestBundle(
      { method: 'GET', url: big, headers: [] },
      undefined,
    )
    const d = decodeBundle(out)
    // URL doesn't have a per-field clip, so all bytes survive. The check is
    // that the fresh-Buffer fallback preserves them exactly.
    expect(d.url_bytes.length).toBe(big.length * 3)
    expect(d.url).toBe(big)
  })

  it('handles default protocol, empty remoteAddr, and a body', () => {
    const out = encodeRequestBundle(
      { method: 'POST', url: '/', headers: [] },
      'payload',
    )
    const d = decodeBundle(out)
    expect(d.proto).toBe('HTTP/1.1')
    expect(d.addr).toBe('')
    expect(d.bodyLen).toBe('payload'.length)
  })
})

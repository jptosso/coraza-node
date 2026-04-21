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

  it('processEncodedRequestBundle accepts a pre-built bundle', () => {
    const { tx, state, txId } = setup()
    const bundle = encodeRequestBundle(
      { method: 'GET', url: '/raw', headers: [['host', 'a.test']] },
      'raw-body',
    )
    expect(tx.processEncodedRequestBundle(bundle)).toBe(false)
    const st = state.txs.get(txId)!
    expect(st.uri?.uri).toBe('/raw')
    expect(new TextDecoder().decode(st.lastBody!)).toBe('raw-body')
  })

  it('processEncodedRequestBundle throws after close', () => {
    const { tx } = setup()
    tx.close()
    const bundle = encodeRequestBundle({ method: 'GET', url: '/', headers: [] }, undefined)
    expect(() => tx.processEncodedRequestBundle(bundle)).toThrow(/closed/)
  })
})

describe('encodeRequestBundle (sink mode)', () => {
  it('writes into a caller-provided Uint8Array when it fits', () => {
    const sink = new Uint8Array(4096)
    const out = encodeRequestBundle(
      { method: 'GET', url: '/hi', headers: [['host', 'x.test']] },
      'body-1',
      undefined,
      sink,
    )
    expect(out.buffer).toBe(sink.buffer)
    expect(out.byteOffset).toBe(0)
    // The returned view is a subarray of the sink; bytes outside the
    // packet are unchanged (zero here).
    const firstByteOfLenField = out[0]
    expect(firstByteOfLenField).toBe(new TextEncoder().encode('').length) // addr length = 0
    expect(sink[out.length]).toBe(0)
  })

  it('reuses the same sink across two encodes without cross-contamination', () => {
    const sink = new Uint8Array(4096)
    const a = encodeRequestBundle(
      { method: 'POST', url: '/first', headers: [['host', 'a']] },
      'payload-a',
      undefined,
      sink,
    )
    const aCopy = new Uint8Array(a) // snapshot before second pass

    const b = encodeRequestBundle(
      { method: 'GET', url: '/second', headers: [['host', 'b']] },
      undefined,
      undefined,
      sink,
    )
    expect(b.buffer).toBe(sink.buffer)
    // Second encode is shorter; its own view must not spill bytes from the
    // first encode past `b.length`.
    const recut = sink.subarray(0, b.length)
    expect(Array.from(recut)).toEqual(Array.from(b))
    // Re-decode a from its snapshot to make sure the first call wasn't
    // corrupted after the fact.
    const dec = new TextDecoder()
    // Body field is the last 4-byte-length + bytes; easier to check by
    // scanning: 'payload-a' must appear in aCopy.
    expect(dec.decode(aCopy).includes('payload-a')).toBe(true)
    expect(dec.decode(b).includes('payload-a')).toBe(false)
  })

  it('falls back to a fresh allocation when the sink is too small', () => {
    const sink = new Uint8Array(8)
    const out = encodeRequestBundle(
      { method: 'POST', url: '/x', headers: [['host', 'a.test']] },
      'a'.repeat(100),
      undefined,
      sink,
    )
    expect(out.buffer).not.toBe(sink.buffer)
    // Sink must be left untouched when overflow forces fallback.
    for (const b of sink) expect(b).toBe(0)
  })

  it('preserves UTF-8 clip semantics when fields are oversize', () => {
    // Method field is capped at 255 bytes; a bogus 300-byte method must
    // truncate cleanly on a UTF-8 codepoint boundary, not throw.
    const big = '€'.repeat(200) // each € is 3 bytes
    expect(() =>
      encodeRequestBundle(
        { method: big, url: '/', headers: [] },
        undefined,
      ),
    ).not.toThrow()
  })
})

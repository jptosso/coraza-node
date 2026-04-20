import { describe, it, expect } from 'vitest'
import { Abi, encodeHeaders, utf8, ABI_MAJOR } from '../src/abi.js'
import { createMock } from './mockAbi.js'

describe('Abi', () => {
  it('rejects incompatible major versions', () => {
    const { exports } = createMock({ abiVersion: 2 << 16 })
    expect(() => new Abi(exports)).toThrow(/incompatible.*major/i)
  })

  it('accepts matching major version', () => {
    const { exports } = createMock()
    const abi = new Abi(exports)
    expect(abi).toBeInstanceOf(Abi)
    expect(ABI_MAJOR).toBe(1)
  })

  it('refreshes memory view when buffer changes', () => {
    const { exports } = createMock()
    const abi = new Abi(exports)
    const first = abi.bytes()
    expect(first).toBeInstanceOf(Uint8Array)
    // Replace the underlying buffer to simulate a WASM memory grow.
    const grown = new ArrayBuffer(first.buffer.byteLength * 2)
    ;(exports.memory as unknown as { buffer: ArrayBuffer }).buffer = grown
    const second = abi.bytes()
    expect(second.buffer).toBe(grown)
    expect(second).not.toBe(first)
    // Third call returns the same (cached) view.
    expect(abi.bytes()).toBe(second)
  })

  it('reads strings, empty string short-circuits', () => {
    const { exports } = createMock()
    const abi = new Abi(exports)
    abi.writeAt(0, utf8('hello'))
    expect(abi.readString(0, 5)).toBe('hello')
    expect(abi.readString(0, 0)).toBe('')
  })

  it('read returns a fresh copy, or empty on zero length', () => {
    const { exports } = createMock()
    const abi = new Abi(exports)
    abi.writeAt(0, new Uint8Array([1, 2, 3]))
    const a = abi.read(0, 3)
    expect(Array.from(a)).toEqual([1, 2, 3])
    // Mutating memory afterwards doesn't alter the returned copy.
    abi.writeAt(0, new Uint8Array([9, 9, 9]))
    expect(Array.from(a)).toEqual([1, 2, 3])
    expect(abi.read(0, 0).length).toBe(0)
  })

  it('unpacks (ptr, len) i64', () => {
    const { exports } = createMock()
    const abi = new Abi(exports)
    const packed = (100n << 32n) | 42n
    expect(abi.unpackSlice(packed)).toEqual({ ptr: 100, len: 42 })
  })

  it('lastError returns empty string when no error, else decoded message', () => {
    const { exports, state } = createMock()
    const abi = new Abi(exports)
    expect(abi.lastError()).toBe('')
    state.lastError = 'boom'
    expect(abi.lastError()).toBe('boom')
  })

  it('check throws on negative rc with attached message', () => {
    const { exports, state } = createMock()
    const abi = new Abi(exports)
    state.lastError = 'rule parse failed'
    expect(() => abi.check(-1, 'waf_create')).toThrow(/waf_create: rule parse failed/)
  })

  it('check falls back to "unknown error" when no last error is set', () => {
    const { exports } = createMock()
    const abi = new Abi(exports)
    expect(() => abi.check(-1, 'op')).toThrow(/op: unknown error/)
  })

  it('check passes through non-negative rc', () => {
    const { exports } = createMock()
    const abi = new Abi(exports)
    abi.check(0, 'ok')
    abi.check(1, 'also ok')
  })
})

describe('encodeHeaders', () => {
  it('encodes empty header list as just the count field', () => {
    const out = encodeHeaders([])
    expect(out.length).toBe(4)
    expect(new DataView(out.buffer, out.byteOffset, 4).getUint32(0, true)).toBe(0)
  })

  it('encodes name/value pairs with length prefixes', () => {
    const out = encodeHeaders([
      ['Host', 'example.com'],
      ['Content-Type', 'application/json'],
    ])
    const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
    expect(view.getUint32(0, true)).toBe(2)
    const dec = new TextDecoder()
    // first entry
    let off = 4
    const nl1 = view.getUint32(off, true)
    off += 4
    expect(dec.decode(out.subarray(off, off + nl1))).toBe('Host')
    off += nl1
    const vl1 = view.getUint32(off, true)
    off += 4
    expect(dec.decode(out.subarray(off, off + vl1))).toBe('example.com')
  })

  it('reuses caller-provided buffer when sufficient', () => {
    const buf = { current: new Uint8Array(1024) }
    const first = encodeHeaders([['a', 'b']], buf)
    expect(first.buffer).toBe(buf.current.buffer)
    const originalBacking = buf.current
    encodeHeaders([['c', 'd']], buf)
    // Same backing array kept.
    expect(buf.current).toBe(originalBacking)
  })

  it('grows buffer when undersized and updates the ref', () => {
    const buf = { current: new Uint8Array(4) } // tiny — cannot fit count+payload
    const out = encodeHeaders([['k', 'v']], buf)
    expect(buf.current).toBe(out)
    expect(out.length).toBeGreaterThan(4)
  })

  it('works without any buffer ref', () => {
    const out = encodeHeaders([['x', 'y']])
    expect(out.length).toBeGreaterThan(4)
  })
})

describe('utf8', () => {
  it('encodes strings to UTF-8 bytes', () => {
    expect(Array.from(utf8('abc'))).toEqual([97, 98, 99])
    expect(utf8('').length).toBe(0)
  })
})

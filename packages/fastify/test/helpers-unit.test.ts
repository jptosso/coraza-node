// Unit tests for the internal helper module. Kept separate from the
// end-to-end plugin tests because these probe edge cases (null / array
// headers / circular JSON / non-object primitives) that the plugin
// path doesn't organically exercise.
//
// IMPORTANT: imports from the internal `helpers.js` relative path.
// These symbols are deliberately NOT in the public `@coraza/fastify`
// surface — tests reach past the facade on purpose.

import { describe, it, expect } from 'vitest'
import { headersOf, serializeBody, payloadToBytes } from '../src/helpers.js'

describe('headersOf', () => {
  it('skips undefined, unrolls arrays, stringifies numbers', () => {
    expect(
      headersOf({
        a: 'x',
        b: ['y', 'z'],
        c: undefined,
        d: 42,
      }),
    ).toEqual([
      ['a', 'x'],
      ['b', 'y'],
      ['b', 'z'],
      ['d', '42'],
    ])
  })
})

describe('serializeBody', () => {
  const decode = (b: Uint8Array | undefined) =>
    b ? new TextDecoder().decode(b) : undefined

  it('returns undefined for null/undefined/empty', () => {
    expect(serializeBody(undefined)).toBeUndefined()
    expect(serializeBody(null)).toBeUndefined()
  })
  it('passes through Uint8Array', () => {
    const buf = new Uint8Array([1, 2, 3])
    expect(serializeBody(buf)).toBe(buf)
  })
  it('utf8-encodes strings', () => {
    expect(decode(serializeBody('hi'))).toBe('hi')
  })
  it('json-stringifies objects', () => {
    expect(decode(serializeBody({ a: 1 }))).toBe('{"a":1}')
  })
  it('returns undefined on circular references', () => {
    const c: Record<string, unknown> = {}
    c.self = c
    expect(serializeBody(c)).toBeUndefined()
  })
})

describe('payloadToBytes', () => {
  const decode = (b: Uint8Array | undefined) =>
    b ? new TextDecoder().decode(b) : undefined

  it('passes through Uint8Array', () => {
    const buf = new Uint8Array([9])
    expect(payloadToBytes(buf)).toBe(buf)
  })
  it('utf8-encodes strings', () => {
    expect(decode(payloadToBytes('hello'))).toBe('hello')
  })
  it('json-stringifies objects', () => {
    expect(decode(payloadToBytes({ leak: 'secret' }))).toBe('{"leak":"secret"}')
  })
  it('returns undefined for non-object primitives like numbers', () => {
    expect(payloadToBytes(42)).toBeUndefined()
    expect(payloadToBytes(true)).toBeUndefined()
  })
  it('returns undefined on circular references', () => {
    const c: Record<string, unknown> = {}
    c.self = c
    expect(payloadToBytes(c)).toBeUndefined()
  })
})

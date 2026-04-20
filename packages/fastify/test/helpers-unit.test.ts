import { describe, it, expect } from 'vitest'
import { headersOf, serializeBody, payloadToBytes } from '../src/index.js'

describe('headersOf', () => {
  it('skips undefined, unrolls arrays, stringifies numbers', () => {
    const out = [
      ...headersOf({
        a: 'x',
        b: ['y', 'z'],
        c: undefined,
        d: 42,
      }),
    ]
    expect(out).toEqual([
      ['a', 'x'],
      ['b', 'y'],
      ['b', 'z'],
      ['d', '42'],
    ])
  })
})

describe('serializeBody', () => {
  it('returns undefined for null/undefined/empty', () => {
    expect(serializeBody(undefined)).toBeUndefined()
    expect(serializeBody(null)).toBeUndefined()
  })
  it('passes through Uint8Array', () => {
    const u = new Uint8Array([1, 2])
    expect(serializeBody(u)).toBe(u)
  })
  it('utf8-encodes strings', () => {
    expect(Array.from(serializeBody('hi')!)).toEqual([104, 105])
  })
  it('json-stringifies objects', () => {
    expect(new TextDecoder().decode(serializeBody({ a: 1 })!)).toBe('{"a":1}')
  })
  it('returns undefined on circular references', () => {
    const circular: Record<string, unknown> = {}
    circular['self'] = circular
    expect(serializeBody(circular)).toBeUndefined()
  })
})

describe('payloadToBytes', () => {
  it('passes through Uint8Array', () => {
    const u = new Uint8Array([1])
    expect(payloadToBytes(u)).toBe(u)
  })
  it('utf8-encodes strings', () => {
    expect(new TextDecoder().decode(payloadToBytes('ok')!)).toBe('ok')
  })
  it('json-stringifies objects', () => {
    expect(new TextDecoder().decode(payloadToBytes({ x: 'y' })!)).toBe('{"x":"y"}')
  })
  it('returns undefined for non-object primitives like numbers', () => {
    expect(payloadToBytes(42)).toBeUndefined()
    expect(payloadToBytes(null)).toBeUndefined()
    expect(payloadToBytes(undefined)).toBeUndefined()
  })
  it('returns undefined on circular references', () => {
    const circular: Record<string, unknown> = {}
    circular['self'] = circular
    expect(payloadToBytes(circular)).toBeUndefined()
  })
})

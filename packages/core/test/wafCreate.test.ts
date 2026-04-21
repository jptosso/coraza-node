// Tests for WAF.create() + createWAF(), which wraps instantiate(). We mock
// the wasm module so no real WASI binary is needed; this also keeps wasm.ts
// out of unit-coverage (it's tested end-to-end in adapter E2Es).

import { describe, it, expect, vi } from 'vitest'
import { Abi } from '../src/abi.js'
import { createMock } from './mockAbi.js'

const { mockInstantiate } = vi.hoisted(() => {
  return { mockInstantiate: vi.fn() }
})

vi.mock('../src/wasm.js', () => ({
  instantiate: mockInstantiate,
}))

describe('createWAF / WAF.create', () => {
  it('delegates to instantiate with the provided wasmSource', async () => {
    const { exports } = createMock()
    const abi = new Abi(exports)
    mockInstantiate.mockResolvedValue(abi)

    const { createWAF, WAF } = await import('../src/waf.js')
    const waf = await createWAF({ rules: 'SecRuleEngine On', mode: 'block', wasmSource: 'ignored' })

    expect(waf).toBeInstanceOf(WAF)
    expect(waf.mode).toBe('block')
    expect(mockInstantiate).toHaveBeenCalledWith(
      'ignored',
      expect.objectContaining({ debug: expect.any(Function) }),
      undefined,
    )

    waf.destroy()
  })

  it('falls back to default wasmSource when not provided', async () => {
    mockInstantiate.mockClear()
    const { exports } = createMock()
    const abi = new Abi(exports)
    mockInstantiate.mockResolvedValue(abi)

    const { createWAF } = await import('../src/waf.js')
    const waf = await createWAF({ rules: '' })

    expect(mockInstantiate).toHaveBeenCalledTimes(1)
    const source = mockInstantiate.mock.calls[0]![0]
    // Default fallback is a file:// URL pointing to the shipped wasm.
    expect(source).toBeInstanceOf(URL)
    expect((source as URL).pathname).toMatch(/coraza\.wasm$/)

    waf.destroy()
  })

  it('defaults mode to "detect" and logger to console', async () => {
    mockInstantiate.mockClear()
    const { exports } = createMock()
    const abi = new Abi(exports)
    mockInstantiate.mockResolvedValue(abi)

    const { createWAF } = await import('../src/waf.js')
    const waf = await createWAF({ rules: '' })
    expect(waf.mode).toBe('detect')
    expect(waf.logger).toBeDefined()
    waf.destroy()
  })
})

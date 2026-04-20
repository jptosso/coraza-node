import 'reflect-metadata'
import { describe, it, expect, vi } from 'vitest'

// Mock @coraza/core's createWAF before importing the module — we don't want
// to boot a real WASM during module unit tests.
const { mockCreateWAF } = vi.hoisted(() => ({
  mockCreateWAF: vi.fn(),
}))

vi.mock('@coraza/core', async () => {
  const actual = await vi.importActual<typeof import('@coraza/core')>('@coraza/core')
  return { ...actual, createWAF: mockCreateWAF }
})

describe('CorazaModule', () => {
  it('forRoot wires CORAZA_WAF provider and optionally APP_GUARD', async () => {
    const { CorazaModule } = await import('../src/coraza.module.js')
    const { CORAZA_WAF, CORAZA_OPTIONS } = await import('../src/tokens.js')

    const dyn = CorazaModule.forRoot({ rules: 'SecRuleEngine On' })
    expect(dyn.module).toBe(CorazaModule)
    expect(dyn.global).toBe(true)
    // Expect at least CORAZA_OPTIONS, CORAZA_WAF provider, CorazaGuard, and APP_GUARD (global).
    const tokens = (dyn.providers ?? []).map((p) => {
      if ('provide' in (p as Record<string, unknown>)) {
        return (p as { provide: unknown }).provide
      }
      return p
    })
    expect(tokens).toContain(CORAZA_OPTIONS)
    expect(tokens).toContain(CORAZA_WAF)
    expect(tokens).toContain('APP_GUARD')
    expect(dyn.exports).toContain(CORAZA_WAF)
  })

  it('forRoot without global guard omits APP_GUARD', async () => {
    const { CorazaModule } = await import('../src/coraza.module.js')
    const dyn = CorazaModule.forRoot({ rules: '', globalGuard: false })
    const tokens = (dyn.providers ?? []).map((p) =>
      'provide' in (p as Record<string, unknown>) ? (p as { provide: unknown }).provide : p,
    )
    expect(tokens).not.toContain('APP_GUARD')
  })

  it('forRootAsync wires an async factory for CORAZA_OPTIONS', async () => {
    const { CorazaModule } = await import('../src/coraza.module.js')
    const { CORAZA_OPTIONS, CORAZA_WAF } = await import('../src/tokens.js')
    const factory = vi.fn(async () => ({ rules: 'rules' }))
    const dyn = CorazaModule.forRootAsync({ useFactory: factory })
    const optsProvider = (dyn.providers ?? []).find(
      (p) =>
        'provide' in (p as Record<string, unknown>) &&
        (p as { provide: unknown }).provide === CORAZA_OPTIONS,
    ) as { useFactory?: typeof factory } | undefined
    expect(optsProvider?.useFactory).toBe(factory)

    const tokens = (dyn.providers ?? []).map((p) =>
      'provide' in (p as Record<string, unknown>) ? (p as { provide: unknown }).provide : p,
    )
    expect(tokens).toContain(CORAZA_WAF)
    expect(tokens).toContain('APP_GUARD')
  })

  it('forRootAsync respects globalGuard: false', async () => {
    const { CorazaModule } = await import('../src/coraza.module.js')
    const dyn = CorazaModule.forRootAsync({ useFactory: () => ({ rules: '' }), globalGuard: false })
    const tokens = (dyn.providers ?? []).map((p) =>
      'provide' in (p as Record<string, unknown>) ? (p as { provide: unknown }).provide : p,
    )
    expect(tokens).not.toContain('APP_GUARD')
  })

  it('CORAZA_WAF useFactory calls createWAF with the resolved options', async () => {
    mockCreateWAF.mockResolvedValue({ destroy: () => {} } as unknown as never)
    const { CorazaModule } = await import('../src/coraza.module.js')
    const { CORAZA_WAF } = await import('../src/tokens.js')

    const dyn = CorazaModule.forRoot({ rules: 'my rules', mode: 'block' })
    const wafProvider = (dyn.providers ?? []).find(
      (p) =>
        'provide' in (p as Record<string, unknown>) &&
        (p as { provide: unknown }).provide === CORAZA_WAF,
    ) as { useFactory: (opts: unknown) => Promise<unknown>; inject: unknown[] }

    const opts = { rules: 'my rules', mode: 'block' }
    const result = await wafProvider.useFactory(opts)
    expect(mockCreateWAF).toHaveBeenCalledWith(opts)
    expect(result).toBeTruthy()
  })

  it('forRootAsync inject is forwarded', async () => {
    const { CorazaModule } = await import('../src/coraza.module.js')
    const { CORAZA_OPTIONS } = await import('../src/tokens.js')
    const dyn = CorazaModule.forRootAsync({
      useFactory: () => ({ rules: '' }),
      inject: ['MY_DEP'],
    })
    const optsProvider = (dyn.providers ?? []).find(
      (p) =>
        'provide' in (p as Record<string, unknown>) &&
        (p as { provide: unknown }).provide === CORAZA_OPTIONS,
    ) as { inject?: unknown[] } | undefined
    expect(optsProvider?.inject).toEqual(['MY_DEP'])
  })
})

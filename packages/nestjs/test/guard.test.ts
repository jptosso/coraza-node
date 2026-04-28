import 'reflect-metadata'
import { describe, it, expect } from 'vitest'
import { ExecutionContext, HttpException } from '@nestjs/common'
import { CorazaGuard } from '../src/coraza.guard.js'
import { mockWAF } from './helpers.js'

function ctx(req: Record<string, unknown>, res: Record<string, unknown> = {}): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: <T>() => req as T,
      getResponse: <T>() => res as T,
      getNext: <T>() => undefined as T,
    }),
    getClass: () => undefined as never,
    getHandler: () => undefined as never,
    getArgs: () => [] as never,
    getArgByIndex: () => undefined as never,
    getType: () => 'http' as never,
    switchToRpc: () => undefined as never,
    switchToWs: () => undefined as never,
  } as unknown as ExecutionContext
}

describe('CorazaGuard', () => {
  it('allows benign requests (canActivate === true)', async () => {
    const { waf } = mockWAF('block')
    const guard = new CorazaGuard(waf)
    const ok = await guard.canActivate(
      ctx({
        method: 'GET',
        url: '/',
        headers: {},
        socket: { remotePort: 1, localPort: 2 },
        ip: '1.2.3.4',
        httpVersion: '1.1',
      }),
    )
    expect(ok).toBe(true)
  })

  it('throws HttpException on header interrupt', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 111, action: 'deny', status: 403, data: 'h' }),
    })
    const guard = new CorazaGuard(waf)
    await expect(
      guard.canActivate(ctx({ method: 'GET', url: '/', headers: {}, socket: {} })),
    ).rejects.toThrow(HttpException)
  })

  it('throws HttpException on body interrupt', async () => {
    const { waf } = mockWAF('block', {
      onBody: () => ({ ruleId: 222, action: 'deny', status: 403, data: 'b' }),
    })
    const guard = new CorazaGuard(waf)
    await expect(
      guard.canActivate(
        ctx({
          method: 'POST',
          url: '/',
          headers: { 'content-type': 'application/json' },
          body: { attack: '<script>' },
          socket: {},
        }),
      ),
    ).rejects.toThrow(/222/)
  })

  it('short-circuits when isRuleEngineOff', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.ruleEngineOff = true
    const guard = new CorazaGuard(waf)
    const ok = await guard.canActivate(
      ctx({ method: 'GET', url: '/attack?q=x', headers: {}, socket: {} }),
    )
    expect(ok).toBe(true)
  })

  it('runs body phase regardless of isRequestBodyAccessible (bundle always fires phase 2)', async () => {
    // Fused bundle runs phase 2 even on body-less verbs so CRS's
    // anomaly-score evaluator always fires. See docs/threat-model.md.
    const { waf, state } = mockWAF('block', {
      onBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.reqBodyAccessible = false
    const guard = new CorazaGuard(waf)
    await expect(
      guard.canActivate(
        ctx({
          method: 'POST',
          url: '/',
          headers: {},
          body: { hi: 1 },
          socket: {},
        }),
      ),
    ).rejects.toThrow(HttpException)
  })

  it('throws HttpException when newTransaction itself fails (default fail-closed)', async () => {
    const { waf } = mockWAF('block')
    waf.newTransaction = () => {
      throw new Error('WAF not ready')
    }
    const guard = new CorazaGuard(waf)
    await expect(
      guard.canActivate(ctx({ method: 'GET', url: '/', headers: {}, socket: {} })),
    ).rejects.toMatchObject({ getStatus: expect.any(Function) })
  })

  it('onWAFError: allow returns true when newTransaction fails', async () => {
    const { waf } = mockWAF('block')
    waf.newTransaction = () => {
      throw new Error('WAF not ready')
    }
    const guard = new CorazaGuard(waf, { onWAFError: 'allow' })
    const ok = await guard.canActivate(
      ctx({ method: 'GET', url: '/', headers: {}, socket: {} }),
    )
    expect(ok).toBe(true)
  })

  it('fails closed (503) when WAF itself throws (default)', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequestBundle = () => {
        throw new Error('boom')
      }
      return tx
    }
    const guard = new CorazaGuard(waf)
    await expect(
      guard.canActivate(ctx({ method: 'GET', url: '/', headers: {}, socket: {} })),
    ).rejects.toMatchObject({ getStatus: expect.any(Function) })
  })

  it('onWAFError: allow continues through WAF internal error', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequestBundle = () => {
        throw new Error('boom')
      }
      return tx
    }
    const guard = new CorazaGuard(waf, { onWAFError: 'allow' })
    const ok = await guard.canActivate(ctx({ method: 'GET', url: '/', headers: {}, socket: {} }))
    expect(ok).toBe(true)
  })

  it('handles multi-value headers, array body, primitive body', async () => {
    const { waf } = mockWAF('block')
    const guard = new CorazaGuard(waf)
    // multi-value header
    await guard.canActivate(
      ctx({
        method: 'GET',
        url: '/',
        originalUrl: '/orig',
        headers: { 'x-custom': ['a', 'b'], 'x-undef': undefined },
        socket: {},
      }),
    )
    // primitive body
    await guard.canActivate(
      ctx({
        method: 'POST',
        url: '/',
        headers: {},
        body: 42,
        socket: {},
      }),
    )
    // empty object body
    await guard.canActivate(
      ctx({
        method: 'POST',
        url: '/',
        headers: {},
        body: {},
        socket: {},
      }),
    )
    // string body
    await guard.canActivate(
      ctx({
        method: 'POST',
        url: '/',
        headers: {},
        body: 'raw-text-body',
        socket: {},
      }),
    )
    // Uint8Array body
    await guard.canActivate(
      ctx({
        method: 'POST',
        url: '/',
        headers: {},
        body: new Uint8Array([1, 2, 3]),
        socket: {},
      }),
    )
    // circular body
    const circular: Record<string, unknown> = {}
    circular['self'] = circular
    await guard.canActivate(
      ctx({
        method: 'POST',
        url: '/',
        headers: {},
        body: circular,
        socket: {},
      }),
    )
  })

  it('bypasses static paths via skip option', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const guard = new CorazaGuard(waf, {})
    const ok = await guard.canActivate(
      ctx({ method: 'GET', url: '/img/logo.png', headers: {}, socket: {} }),
    )
    expect(ok).toBe(true)
  })

  it('skip: false still blocks static paths', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const guard = new CorazaGuard(waf, { skip: false })
    await expect(
      guard.canActivate(ctx({ method: 'GET', url: '/img/logo.png', headers: {}, socket: {} })),
    ).rejects.toThrow()
  })

  it('uses req.raw.httpVersion when req.httpVersion is missing (Fastify path)', async () => {
    const { waf } = mockWAF('block')
    const guard = new CorazaGuard(waf)
    const ok = await guard.canActivate(
      ctx({
        method: 'GET',
        url: '/',
        headers: {},
        socket: {},
        raw: { httpVersion: '2.0' },
      }),
    )
    expect(ok).toBe(true)
  })

  it('ignore: { methods } skips entirely', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const guard = new CorazaGuard(waf, { ignore: { methods: ['OPTIONS'] } })
    const ok = await guard.canActivate(
      ctx({ method: 'OPTIONS', url: '/api', headers: {}, socket: {} }),
    )
    expect(ok).toBe(true)
  })

  it('ignore: { headerEquals } bypasses on matching header', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const guard = new CorazaGuard(waf, {
      ignore: { headerEquals: { 'x-internal': 'yes' } },
    })
    const ok = await guard.canActivate(
      ctx({ method: 'GET', url: '/api', headers: { 'x-internal': 'yes' }, socket: {} }),
    )
    expect(ok).toBe(true)
  })

  it('ignore: { bodyLargerThan } skips body inspection (URL+headers still run)', async () => {
    const { waf } = mockWAF('block', {
      onBody: (tx) =>
        tx.lastBody && tx.lastBody.length > 0
          ? { ruleId: 941100, action: 'deny', status: 403, data: 'XSS' }
          : undefined,
    })
    const guard = new CorazaGuard(waf, { ignore: { bodyLargerThan: 100 } })
    const ok = await guard.canActivate(
      ctx({
        method: 'POST',
        url: '/upload',
        headers: { 'content-length': '5000', 'content-type': 'application/json' },
        body: { x: '<script>'.repeat(100) },
        socket: {},
      }),
    )
    expect(ok).toBe(true) // body wasn't sent to the bundle
  })

  it('ignore: { match } most-restrictive merges with declarative skip', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const guard = new CorazaGuard(waf, {
      ignore: {
        routes: ['/healthz'],
        match: (c) =>
          (c.headers as Map<string, string>).get('x-suspicious') === 'yes' ? false : true,
      },
    })
    const ok = await guard.canActivate(
      ctx({ method: 'GET', url: '/healthz', headers: {}, socket: {} }),
    )
    expect(ok).toBe(true)
    await expect(
      guard.canActivate(
        ctx({
          method: 'GET',
          url: '/healthz',
          headers: { 'x-suspicious': 'yes' },
          socket: {},
        }),
      ),
    ).rejects.toThrow()
  })

  it('legacy skip: still maps to ignore: shape', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const guard = new CorazaGuard(waf, { skip: { prefixes: ['/healthz'] } })
    const ok = await guard.canActivate(
      ctx({ method: 'GET', url: '/healthz', headers: {}, socket: {} }),
    )
    expect(ok).toBe(true)
  })

  it('ignore: false disables bypass', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const guard = new CorazaGuard(waf, { ignore: false })
    await expect(
      guard.canActivate(ctx({ method: 'GET', url: '/img/logo.png', headers: {}, socket: {} })),
    ).rejects.toThrow()
  })

  // Issue #23 — block log loses signal. Default block line MUST include
  // `interruption.data` (free) and verboseLog: true MUST surface every
  // matching rule and pass them to onBlock(ctx).
  it('issue #23: passes matchedRules to onBlock when verboseLog is enabled', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: (tx) => {
        tx.matchedRules = [{ id: 942100, severity: 2, message: 'SQLi' }]
        return { ruleId: 949110, action: 'deny', status: 403, data: 'anomaly' }
      },
    })
    let received: unknown = 'unset'
    const onBlock = (i: { ruleId: number }, c?: { matchedRules: unknown }): HttpException => {
      received = c
      return new HttpException(`blocked ${i.ruleId}`, 403)
    }
    const guard = new CorazaGuard(waf, { verboseLog: true, onBlock })
    await expect(
      guard.canActivate(ctx({ method: 'GET', url: '/x', headers: {}, socket: {} })),
    ).rejects.toThrow(HttpException)
    expect(received).toEqual({ matchedRules: [{ id: 942100, severity: 2, message: 'SQLi' }] })
  })

  // Issue #24 — multi-value list-form headers MUST reach the WAF as
  // separate entries. NestJS bridges to either Express or Fastify;
  // both expose Node's IncomingMessage with `rawHeaders` (Express:
  // `req.rawHeaders`; Fastify: `req.raw.rawHeaders`). We prefer
  // either over the comma-joined `req.headers`.
  it('issue #24: multi-value X-Forwarded-For reaches the WAF as separate entries', async () => {
    const captured: Array<[string, string]> = []
    const { waf } = mockWAF('block', {
      onHeaders: (tx) => {
        captured.push(...tx.headers)
        return undefined
      },
    })
    const guard = new CorazaGuard(waf)
    await guard.canActivate(
      ctx({
        method: 'GET',
        url: '/',
        headers: { host: 'localhost' },
        rawHeaders: [
          'Host', 'localhost',
          'X-Forwarded-For', '203.0.113.5',
          'X-Forwarded-For', '198.51.100.7',
        ],
        socket: {},
      }),
    )
    const xff = captured.filter(([k]) => k === 'x-forwarded-for').map(([, v]) => v)
    expect(xff).toEqual(['203.0.113.5', '198.51.100.7'])
  })
})

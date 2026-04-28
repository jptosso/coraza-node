import { describe, it, expect, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { coraza, defaultBlock } from '../src/index.js'
import { mockWAF } from './helpers.js'

async function appWith(
  wafOpts: Parameters<typeof mockWAF>[1] = {},
  pluginOpts: Record<string, unknown> = {},
): Promise<{ app: FastifyInstance; state: ReturnType<typeof mockWAF>['state'] }> {
  const { waf, state } = mockWAF('block', wafOpts)
  const app = Fastify({ logger: false })
  await app.register(coraza, { waf, ...pluginOpts })
  app.get('/hi', async () => ({ ok: true }))
  app.post('/echo', async (req) => req.body)
  // Do NOT call ready() — inject() triggers it lazily, and tests can still
  // add routes beforehand.
  return { app, state }
}

describe('@coraza/fastify', () => {
  it('passes benign requests through and closes tx', async () => {
    const { app, state } = await appWith()
    const res = await app.inject({ method: 'GET', url: '/hi' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ ok: true })
    // onResponse hook closed the transaction
    expect(state.txs.size).toBe(0)
    await app.close()
  })

  it('blocks on request header interruption', async () => {
    const { app } = await appWith({
      onHeaders: () => ({ ruleId: 100, action: 'deny', status: 403, data: 'hdr' }),
    })
    const res = await app.inject({ method: 'GET', url: '/hi' })
    expect(res.statusCode).toBe(403)
    expect(res.body).toContain('100')
    await app.close()
  })

  it('blocks on request body interruption (after preHandler)', async () => {
    const { app } = await appWith({
      onBody: () => ({ ruleId: 200, action: 'deny', status: 403, data: 'body' }),
    })
    const res = await app.inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/json' },
      payload: { attack: "<script>" },
    })
    expect(res.statusCode).toBe(403)
    expect(res.body).toContain('200')
    await app.close()
  })

  it('short-circuits when isRuleEngineOff', async () => {
    const { app, state } = await appWith({
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.ruleEngineOff = true
    const res = await app.inject({ method: 'GET', url: "/hi?q='OR 1=1--" })
    expect(res.statusCode).toBe(200)
    await app.close()
  })

  it('runs body phase regardless of isRequestBodyAccessible (bundle always fires phase 2)', async () => {
    // Phase 2 runs atomically with phase 1 via the fused bundle. CRS's
    // anomaly-score evaluator lives at phase 2, so it must run on every
    // request — including body-less GETs.
    const { app, state } = await appWith({
      onBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.reqBodyAccessible = false
    const res = await app.inject({
      method: 'POST',
      url: '/echo',
      payload: { hi: 1 },
    })
    expect(res.statusCode).toBe(403)
    await app.close()
  })

  it('honors custom onBlock', async () => {
    const onBlock = vi.fn(async (it, _req, reply) => {
      reply.code(418).send({ blocked: it.ruleId })
    })
    const { app } = await appWith(
      { onHeaders: () => ({ ruleId: 9, action: 'deny', status: 403, data: '' }) },
      { onBlock },
    )
    const res = await app.inject({ method: 'GET', url: '/hi' })
    expect(res.statusCode).toBe(418)
    expect(res.json()).toEqual({ blocked: 9 })
    expect(onBlock).toHaveBeenCalled()
    await app.close()
  })

  it('inspects response body when inspectResponse: true', async () => {
    const { app } = await appWith(
      { onResponseBody: () => ({ ruleId: 333, action: 'deny', status: 403, data: 'leak' }) },
      { inspectResponse: true },
    )
    const res = await app.inject({ method: 'GET', url: '/hi' })
    expect(res.statusCode).toBe(403)
    expect(res.body).toContain('333')
    await app.close()
  })

  it('default config does NOT inspect response', async () => {
    const { app } = await appWith({
      onResponseBody: () => ({ ruleId: 999, action: 'deny', status: 403, data: 'leak' }),
    })
    const res = await app.inject({ method: 'GET', url: '/hi' })
    expect(res.statusCode).toBe(200)
    await app.close()
  })

  it('blocks on response header interruption when inspectResponse: true', async () => {
    const { app } = await appWith(
      { onResponseHeaders: () => ({ ruleId: 444, action: 'deny', status: 403, data: 'hdr' }) },
      { inspectResponse: true },
    )
    const res = await app.inject({ method: 'GET', url: '/hi' })
    expect(res.statusCode).toBe(403)
    expect(res.body).toContain('444')
    await app.close()
  })

  it('inspectResponse: true is a no-op (with a warning) under a pool-shaped WAF', async () => {
    // Mirrors the Express adapter: when the WAF is a WAFPool, response
    // phase hooks can't be registered safely (`processResponse` is async
    // and races Fastify's serialisation path, producing
    // `ERR_HTTP_HEADERS_SENT` crashes mid-request). The plugin should
    // log a single warning at register time and then behave as if
    // inspectResponse were false — not crash, not silently inspect.
    const { waf, state } = mockWAF('block', {
      onResponseBody: () => ({ ruleId: 777, action: 'deny', status: 403, data: 'leak' }),
    })
    // Make `waf.newTransaction` look async — the same shape check the
    // plugin uses to distinguish a WAFPool from a sync WAF.
    const realNew = waf.newTransaction.bind(waf)
    const asyncNew = async function poolLikeNewTransaction() {
      return realNew()
    }
    Object.defineProperty(waf, 'newTransaction', { value: asyncNew, writable: true })
    const warn = vi.fn()
    waf.logger = { ...waf.logger, warn }
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf, inspectResponse: true })
    app.get('/leaky', async () => ({ secret: 'ok' }))
    const res = await app.inject({ method: 'GET', url: '/leaky' })
    expect(res.statusCode).toBe(200) // response inspection skipped — no 403
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('inspectResponse=true is a no-op when using WAFPool'),
    )
    // The onResponseBody stub should never have been reached.
    expect(state.txs.size).toBe(0) // onResponse closed the tx already
    await app.close()
  })

  it('skips response-body phase when isResponseBodyProcessable is false', async () => {
    const { app, state } = await appWith(
      { onResponseBody: () => ({ ruleId: 5, action: 'deny', status: 403, data: 'x' }) },
      { inspectResponse: true },
    )
    state.respBodyProcessable = false
    const res = await app.inject({ method: 'GET', url: '/hi' })
    expect(res.statusCode).toBe(200)
    await app.close()
  })

  it('tolerates response-inspection errors', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processResponse = () => {
        throw new Error('boom')
      }
      return tx
    }
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf, inspectResponse: true })
    app.get('/', async () => 'ok')
    const res = await app.inject({ method: 'GET', url: '/' })
    expect(res.statusCode).toBe(200)
    await app.close()
  })

  it('fails closed (503) when newTransaction itself throws (default)', async () => {
    const { waf } = mockWAF('block')
    waf.newTransaction = () => {
      throw new Error('WAF not ready')
    }
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf })
    app.get('/', async () => 'ok')
    const res = await app.inject({ method: 'GET', url: '/' })
    expect(res.statusCode).toBe(503)
    await app.close()
  })

  it('onWAFError: allow skips the block when newTransaction throws', async () => {
    const { waf } = mockWAF('block')
    waf.newTransaction = () => {
      throw new Error('WAF not ready')
    }
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf, onWAFError: 'allow' })
    app.get('/', async () => 'ok')
    const res = await app.inject({ method: 'GET', url: '/' })
    expect(res.statusCode).toBe(200)
    await app.close()
  })

  it('fails closed (503) when the bundle call itself throws', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequestBundle = () => {
        throw new Error('bundle boom')
      }
      return tx
    }
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf })
    app.get('/', async () => 'ok')
    const res = await app.inject({ method: 'GET', url: '/' })
    expect(res.statusCode).toBe(503)
    await app.close()
  })

  it('onWAFError: allow passes through when the bundle throws', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequestBundle = () => {
        throw new Error('bundle boom')
      }
      return tx
    }
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf, onWAFError: 'allow' })
    app.get('/', async () => 'ok')
    const res = await app.inject({ method: 'GET', url: '/' })
    expect(res.statusCode).toBe(200)
    await app.close()
  })

  it('defaultBlock is a no-op when reply is already sent', () => {
    const reply = {
      sent: true,
      code: vi.fn().mockReturnThis(),
      type: vi.fn().mockReturnThis(),
      send: vi.fn(),
    } as unknown as Parameters<typeof defaultBlock>[2]
    defaultBlock(
      { ruleId: 1, action: 'deny', status: 403, data: '' },
      {} as Parameters<typeof defaultBlock>[1],
      reply,
    )
    expect((reply as unknown as { code: ReturnType<typeof vi.fn> }).code).not.toHaveBeenCalled()
  })

  it('handles multi-value request headers via inject', async () => {
    const { waf, state } = mockWAF('block')
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf })
    app.get('/', async () => 'ok')
    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: { 'set-cookie': ['a=1', 'b=2'] as unknown as string },
    })
    expect(res.statusCode).toBe(200)
    expect(state.txs.size).toBe(0) // closed already
    await app.close()
  })


  it('serializeBody handles string request body', async () => {
    const { waf } = mockWAF('block')
    const app = Fastify({ logger: false })
    // Register a text/plain parser so Fastify leaves req.body as a string.
    app.addContentTypeParser('text/plain', { parseAs: 'string' }, (_req, body, done) => {
      done(null, body)
    })
    await app.register(coraza, { waf })
    app.post('/raw', async (req) => req.body)
    const res = await app.inject({
      method: 'POST',
      url: '/raw',
      headers: { 'content-type': 'text/plain' },
      payload: 'plain-string-body',
    })
    expect(res.statusCode).toBe(200)
    expect(res.body).toBe('plain-string-body')
    await app.close()
  })

  it('serializeBody handles Uint8Array request body (raw parser)', async () => {
    const { waf } = mockWAF('block')
    const app = Fastify({ logger: false })
    app.addContentTypeParser(
      'application/octet-stream',
      { parseAs: 'buffer' },
      (_req, body, done) => {
        done(null, body) // body is a Buffer (which is a Uint8Array)
      },
    )
    await app.register(coraza, { waf })
    app.post('/bin', async () => 'ok')
    const res = await app.inject({
      method: 'POST',
      url: '/bin',
      headers: { 'content-type': 'application/octet-stream' },
      payload: Buffer.from([1, 2, 3]),
    })
    expect(res.statusCode).toBe(200)
    await app.close()
  })

  it('payloadToBytes handles Buffer / string / object response payloads', async () => {
    const { waf } = mockWAF('block')
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf, inspectResponse: true })
    app.get('/obj', async () => ({ a: 1 }))
    app.get('/str', async () => 'plain')
    app.get('/buf', async (_req, reply) => {
      reply.type('application/octet-stream')
      return Buffer.from([1, 2, 3])
    })
    expect((await app.inject({ method: 'GET', url: '/obj' })).statusCode).toBe(200)
    expect((await app.inject({ method: 'GET', url: '/str' })).statusCode).toBe(200)
    expect((await app.inject({ method: 'GET', url: '/buf' })).statusCode).toBe(200)
    await app.close()
  })

  it('bypasses default static paths (no tx created)', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf })
    app.get('/img/logo.png', async () => 'bin')
    app.get('/api', async () => ({ ok: true }))

    const png = await app.inject({ method: 'GET', url: '/img/logo.png' })
    expect(png.statusCode).toBe(200)
    const api = await app.inject({ method: 'GET', url: '/api' })
    expect(api.statusCode).toBe(403)

    expect(state.nextTx).toBe(1)
    await app.close()
  })

  it('skip: false disables bypass', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = Fastify({ logger: false })
    await app.register(coraza, { waf, skip: false })
    app.get('/img/logo.png', async () => 'bin')
    const res = await app.inject({ method: 'GET', url: '/img/logo.png' })
    expect(res.statusCode).toBe(403)
    await app.close()
  })

  it('defaultBlock falls back to 403 when interruption.status is falsy', () => {
    const code = vi.fn().mockReturnThis()
    const reply = {
      sent: false,
      code,
      type: vi.fn().mockReturnThis(),
      send: vi.fn(),
    } as unknown as Parameters<typeof defaultBlock>[2]
    defaultBlock(
      { ruleId: 1, action: 'deny', status: 0, data: '' },
      {} as Parameters<typeof defaultBlock>[1],
      reply,
    )
    expect(code).toHaveBeenCalledWith(403)
  })

  it('ignore: { methods } skips configured methods entirely', async () => {
    const { app, state } = await appWith(
      { onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }) },
      { ignore: { methods: ['OPTIONS'] } },
    )
    app.options('/api', async () => 'ok')
    app.get('/api', async () => 'ok')
    expect((await app.inject({ method: 'OPTIONS', url: '/api' })).statusCode).toBe(200)
    expect((await app.inject({ method: 'GET', url: '/api' })).statusCode).toBe(403)
    expect(state.nextTx).toBe(1)
    await app.close()
  })

  it('ignore: { routes } supports glob and regex routes', async () => {
    const { app } = await appWith(
      { onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }) },
      { ignore: { routes: ['/healthz', /^\/internal/] } },
    )
    app.get('/healthz', async () => 'ok')
    app.get('/internal/x', async () => 'ok')
    app.get('/api', async () => 'ok')
    expect((await app.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200)
    expect((await app.inject({ method: 'GET', url: '/internal/x' })).statusCode).toBe(200)
    expect((await app.inject({ method: 'GET', url: '/api' })).statusCode).toBe(403)
    await app.close()
  })

  it('ignore: { headerEquals } bypasses on matching header', async () => {
    const { app } = await appWith(
      { onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }) },
      { ignore: { headerEquals: { 'x-internal': 'true' } } },
    )
    app.get('/api', async () => 'ok')
    const ok = await app.inject({
      method: 'GET',
      url: '/api',
      headers: { 'x-internal': 'true' },
    })
    expect(ok.statusCode).toBe(200)
    const blocked = await app.inject({ method: 'GET', url: '/api' })
    expect(blocked.statusCode).toBe(403)
    await app.close()
  })

  it('ignore: { bodyLargerThan } returns skip-body and runs URL+headers only', async () => {
    const { app } = await appWith(
      {
        onBody: (tx) =>
          tx.lastBody && tx.lastBody.length > 0
            ? { ruleId: 941100, action: 'deny', status: 403, data: 'XSS' }
            : undefined,
      },
      { ignore: { bodyLargerThan: 100 } },
    )
    const big = JSON.stringify({ msg: '<script>'.repeat(50) })
    const res = await app.inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/json', 'content-length': String(big.length) },
      payload: big,
    })
    expect(res.statusCode).toBe(200)
    await app.close()
  })

  it('ignore: { match } imperative escape hatch overrides declarative skip (most-restrictive)', async () => {
    const { app } = await appWith(
      { onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }) },
      {
        ignore: {
          routes: ['/healthz'],
          match: (ctx) =>
            (ctx.headers as Map<string, string>).get('x-suspicious') === 'yes' ? false : true,
        },
      },
    )
    app.get('/healthz', async () => 'ok')
    expect((await app.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200)
    expect(
      (
        await app.inject({
          method: 'GET',
          url: '/healthz',
          headers: { 'x-suspicious': 'yes' },
        })
      ).statusCode,
    ).toBe(403)
    await app.close()
  })

  it('legacy skip: still works and matches new ignore: shape', async () => {
    const { app } = await appWith(
      { onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }) },
      { skip: { prefixes: ['/healthz'] } },
    )
    app.get('/healthz', async () => 'ok')
    app.get('/api', async () => 'ok')
    expect((await app.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200)
    expect((await app.inject({ method: 'GET', url: '/api' })).statusCode).toBe(403)
    await app.close()
  })

  it('ignore: false disables bypass', async () => {
    const { app } = await appWith(
      { onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }) },
      { ignore: false },
    )
    app.get('/img/logo.png', async () => 'ok')
    expect((await app.inject({ method: 'GET', url: '/img/logo.png' })).statusCode).toBe(403)
    await app.close()
  })

  // Issue #23 — block log loses signal. The default block log line MUST
  // include `interruption.data` and verboseLog: true MUST emit one line
  // per matched rule (so a CRS 949110 anomaly-score block reveals the
  // contributing 941100/942100 hits, not just the threshold rule).
  it('issue #23: default block log includes interruption.data and verboseLog emits matched rules', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: (tx) => {
        tx.matchedRules = [
          { id: 942100, severity: 2, message: 'SQL Injection (libinjection)' },
          { id: 941100, severity: 2, message: 'XSS reflected' },
        ]
        return {
          ruleId: 949110,
          action: 'deny',
          status: 403,
          data: 'Inbound Anomaly Score Exceeded (Total Score: 10)',
        }
      },
    })
    const warn = vi.fn()
    const app = Fastify({ logger: false })
    // Inject a stub logger on every request so we can capture warn lines.
    app.addHook('onRequest', async (req) => {
      ;(req as unknown as { log: { warn: typeof warn } }).log = { warn }
    })
    await app.register(coraza, { waf, verboseLog: true })
    app.get('/x', async () => 'ok')
    await app.inject({ method: 'GET', url: '/x' })
    const calls = warn.mock.calls.map((c) => String(c[0]))
    expect(calls.some((s) => s.includes('request blocked') && s.includes('Inbound Anomaly Score'))).toBe(true)
    expect(calls.some((s) => s.includes('942100') && s.includes('SQL Injection'))).toBe(true)
    expect(calls.some((s) => s.includes('941100'))).toBe(true)
    await app.close()
  })

  // Issue #25 — top-level createWAF rejection is silent. Fastify boot
  // must fail loudly with the original error and `onWAFInit` must fire
  // once with the original Error before the rejection propagates out
  // of `register()`.
  it('issue #25: rejecting waf promise fires onWAFInit and bubbles the original error', async () => {
    const original = new Error('WASM compile failed: ABI version mismatch')
    const onWAFInit = vi.fn()
    const app = Fastify({ logger: false })
    await expect(
      app.register(coraza, {
        waf: Promise.reject(original) as never,
        onWAFInit,
      }),
    ).rejects.toThrow('WASM compile failed: ABI version mismatch')
    expect(onWAFInit).toHaveBeenCalledTimes(1)
    expect(onWAFInit).toHaveBeenCalledWith(original)
    await app.close()
  })
})

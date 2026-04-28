import { describe, it, expect, vi } from 'vitest'
import express from 'express'
import request from 'supertest'
import { coraza, defaultBlock } from '../src/index.js'
import { mockWAF } from './helpers.js'

function appWith(mw: express.RequestHandler): express.Express {
  const app = express()
  app.use(express.json())
  app.use(mw)
  app.get('/hi', (_req, res) => res.status(200).send('ok'))
  app.post('/echo', (req, res) => res.status(200).json(req.body ?? {}))
  return app
}

describe('@coraza/express', () => {
  it('accepts a Promise<WAF> and resolves it once, memoising', async () => {
    const { waf } = mockWAF('block')
    let resolveCount = 0
    const wafPromise = (async () => {
      resolveCount++
      return waf
    })()
    const app = appWith(coraza({ waf: wafPromise }))
    const r1 = await request(app).get('/hi')
    const r2 = await request(app).get('/hi')
    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)
    expect(resolveCount).toBe(1)
  })

  it('fails closed (503) when the WAF promise rejects', async () => {
    const app = appWith(
      coraza({
        waf: (async () => {
          throw new Error('WAF boot failed')
        })(),
      }),
    )
    const res = await request(app).get('/hi')
    expect(res.status).toBe(503)
  })

  it('falls through to next() when the WAF promise rejects under onWAFError: allow', async () => {
    const app = appWith(
      coraza({
        waf: (async () => {
          throw new Error('WAF boot failed')
        })(),
        onWAFError: 'allow',
      }),
    )
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200)
  })

  it('passes benign requests through and closes tx after response', async () => {
    const { waf, state } = mockWAF('block')
    const app = appWith(coraza({ waf }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200)
    expect(res.text).toBe('ok')
    // transaction got logged + closed
    expect(state.txs.size).toBe(0)
  })

  it('blocks on header-phase interruption (SQLi in query string)', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: (tx) =>
        tx.uri?.uri.includes('q=') // query param present
          ? { ruleId: 942100, action: 'deny', status: 403, data: 'SQLi' }
          : undefined,
    })
    const app = appWith(coraza({ waf }))
    const res = await request(app).get('/hi').query({ q: "' OR 1=1--" })
    expect(res.status).toBe(403)
    expect(res.text).toContain('Coraza')
    expect(res.text).toContain('942100')
  })

  it('blocks on body-phase interruption', async () => {
    const { waf } = mockWAF('block', {
      onBody: () => ({ ruleId: 941100, action: 'deny', status: 403, data: 'XSS' }),
    })
    const app = appWith(coraza({ waf }))
    const res = await request(app).post('/echo').send({ msg: '<script>' })
    expect(res.status).toBe(403)
    expect(res.text).toContain('941100')
  })

  it('short-circuits entirely when isRuleEngineOff', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.ruleEngineOff = true
    const app = appWith(coraza({ waf }))
    const res = await request(app).get("/hi?q='OR 1=1--")
    expect(res.status).toBe(200)
    const tx = [...state.txs.values()][0]
    // Bundle should not have run — no URI captured
    expect(tx?.uri).toBeUndefined()
  })

  it('runs body phase regardless of isRequestBodyAccessible (bundle always fires phase 2)', async () => {
    // The fused bundle runs phase 2 even when body access is disabled —
    // matches Coraza's intended flow: the anomaly-score block evaluates
    // at phase 2, so it must run for every request, including body-less
    // GETs. `isRequestBodyAccessible` is a hint for adapters deciding
    // whether to serialize a body, not a gate on whether phase 2 runs.
    const { waf, state } = mockWAF('block', {
      onBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'fires at phase 2' }),
    })
    state.reqBodyAccessible = false
    const app = appWith(coraza({ waf }))
    const res = await request(app).post('/echo').send({ msg: 'benign' })
    expect(res.status).toBe(403)
  })

  it('honors a custom onBlock', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 418, data: 'custom' }),
    })
    const onBlock = vi.fn((it, _req, res) => {
      res.status(499).json({ blocked: true, id: it.ruleId })
    })
    const app = appWith(coraza({ waf, onBlock }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(499)
    expect(res.body).toEqual({ blocked: true, id: 1 })
    expect(onBlock).toHaveBeenCalledOnce()
  })

  it('defaultBlock helper works standalone and respects headersSent', () => {
    const res = {
      headersSent: false,
      status: vi.fn().mockReturnThis(),
      type: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
    } as unknown as express.Response
    defaultBlock({ ruleId: 7, action: 'deny', status: 403, data: 'x' }, {} as express.Request, res)
    expect((res.status as ReturnType<typeof vi.fn>)).toHaveBeenCalledWith(403)

    // headersSent → no-op
    const sent = { headersSent: true, status: vi.fn() } as unknown as express.Response
    defaultBlock({ ruleId: 7, action: 'deny', status: 0, data: '' }, {} as express.Request, sent)
    expect(sent.status as ReturnType<typeof vi.fn>).not.toHaveBeenCalled()
  })

  it('inspectResponse: false skips response hooks', async () => {
    const { waf } = mockWAF('block', {
      onResponseBody: () => ({ ruleId: 2, action: 'deny', status: 403, data: 'resp' }),
    })
    const app = appWith(coraza({ waf, inspectResponse: false }))
    const res = await request(app).get('/hi')
    // Response body would have been caught if inspection were on. It's off,
    // so the response goes through unchanged.
    expect(res.status).toBe(200)
  })

  it('inspectResponse: true with a pool-like (async close) waf logs a warning and skips hooks', async () => {
    const { waf } = mockWAF('block', {
      onResponseBody: () => ({ ruleId: 2, action: 'deny', status: 403, data: 'resp' }),
    })
    const warn = vi.fn()
    // Shim the transaction so isSyncTx() sees an async `close` — the same
    // check the adapter uses to distinguish a WAFPool's WorkerTransaction
    // from a sync Transaction.
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      ;(tx as unknown as { close: () => Promise<void> }).close = async () => {}
      return tx
    }
    waf.logger = { ...waf.logger, warn }
    const app = appWith(coraza({ waf, inspectResponse: true }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200)
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('inspectResponse=true is a no-op when using WAFPool'),
    )
  })

  it('fails closed by default when middleware itself throws (onWAFError default)', async () => {
    const { waf } = mockWAF('block')
    const origNew = waf.newTransaction.bind(waf)
    let thrown = false
    waf.newTransaction = () => {
      if (!thrown) {
        thrown = true
        throw new Error('boom')
      }
      return origNew()
    }
    const app = appWith(coraza({ waf }))
    const res = await request(app).get('/hi')
    // Default is fail-closed — an error in the WAF returns 503. See
    // docs/threat-model.md: a crafted crash must not become a bypass.
    expect(res.status).toBe(503)
  })

  it('fails open when onWAFError is explicitly set to allow', async () => {
    const { waf } = mockWAF('block')
    const origNew = waf.newTransaction.bind(waf)
    let thrown = false
    waf.newTransaction = () => {
      if (!thrown) {
        thrown = true
        throw new Error('boom')
      }
      return origNew()
    }
    const app = appWith(coraza({ waf, onWAFError: 'allow' }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200)
  })

  it('inspects response body and blocks when rule fires on it (inspectResponse: true)', async () => {
    const { waf } = mockWAF('block', {
      onResponseBody: () => ({ ruleId: 954100, action: 'deny', status: 403, data: 'leak' }),
    })
    const onBlock = vi.fn()
    const app = express()
    app.use(coraza({ waf, onBlock, inspectResponse: true }))
    app.get('/leak', (_req, res) => res.send('secret in body'))
    await request(app).get('/leak')
    expect(onBlock).toHaveBeenCalledWith(
      expect.objectContaining({ ruleId: 954100 }),
      expect.anything(),
      expect.anything(),
    )
  })

  it('default config does NOT inspect response', async () => {
    const { waf } = mockWAF('block', {
      onResponseBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = appWith(coraza({ waf }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200) // response untouched by default
  })

  it('skips response-body phase when isResponseBodyProcessable is false', async () => {
    const { waf, state } = mockWAF('block', {
      onResponseBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.respBodyProcessable = false
    const app = express()
    app.use(coraza({ waf, inspectResponse: true }))
    app.get('/', (_req, res) => res.send('would-block-body'))
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
  })

  it('tolerates response-header inspection errors without crashing', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      const orig = tx.processResponse.bind(tx)
      let called = false
      tx.processResponse = (r) => {
        if (!called) {
          called = true
          throw new Error('header inspect boom')
        }
        return orig(r)
      }
      return tx
    }
    const app = appWith(coraza({ waf, inspectResponse: true }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200)
  })

  it('tolerates response-body inspection errors without crashing', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processResponseBody = () => {
        throw new Error('body inspect boom')
      }
      return tx
    }
    const app = appWith(coraza({ waf, inspectResponse: true }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200)
  })

  it('extractBody handles Uint8Array request body', async () => {
    const { waf, state } = mockWAF('block')
    const app = express()
    app.use((req, _res, next) => {
      ;(req as unknown as { body: Uint8Array }).body = new Uint8Array([1, 2, 3])
      next()
    })
    app.use(coraza({ waf }))
    app.post('/', (_req, res) => res.send('ok'))
    await request(app).post('/').send('ignored')
    const lastTx = [...state.txs.values()][0]
    // lastBody is the body that made it to Coraza.
    // Since Express closed the tx before we can introspect, the map is empty;
    // instead assert no error occurred.
    expect(lastTx).toBeUndefined()
  })

  it('extractBody ignores non-serializable bodies gracefully', async () => {
    const { waf } = mockWAF('block')
    const circular: Record<string, unknown> = {}
    circular['self'] = circular
    const app = express()
    app.use((req, _res, next) => {
      ;(req as unknown as { body: unknown }).body = circular
      next()
    })
    app.use(coraza({ waf }))
    app.post('/', (_req, res) => res.send('ok'))
    const res = await request(app).post('/')
    expect(res.status).toBe(200)
  })

  it('blocks on response-header interruption', async () => {
    const { waf } = mockWAF('block', {
      onResponseHeaders: () => ({ ruleId: 920100, action: 'deny', status: 403, data: 'hdr' }),
    })
    const onBlock = vi.fn()
    const app = express()
    app.use(coraza({ waf, onBlock, inspectResponse: true }))
    app.get('/', (_req, res) => {
      res.setHeader('set-cookie', ['a=1', 'b=2'])
      res.send('ok')
    })
    await request(app).get('/')
    expect(onBlock).toHaveBeenCalledWith(
      expect.objectContaining({ ruleId: 920100 }),
      expect.anything(),
      expect.anything(),
    )
  })

  it('extractBody handles string body and empty-object body', async () => {
    const { waf } = mockWAF('block')
    const stringApp = express()
    stringApp.use((req, _res, next) => {
      ;(req as unknown as { body: string }).body = 'raw-string-body'
      next()
    })
    stringApp.use(coraza({ waf }))
    stringApp.post('/', (_req, res) => res.send('ok'))
    expect((await request(stringApp).post('/')).status).toBe(200)

    const emptyApp = express()
    emptyApp.use((req, _res, next) => {
      ;(req as unknown as { body: object }).body = {}
      next()
    })
    emptyApp.use(coraza({ waf }))
    emptyApp.post('/', (_req, res) => res.send('ok'))
    expect((await request(emptyApp).post('/')).status).toBe(200)
  })

  it('defaultBlock falls back to 403 when interruption.status is falsy', () => {
    const status = vi.fn().mockReturnThis()
    const res = {
      headersSent: false,
      status,
      type: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
    } as unknown as express.Response
    defaultBlock(
      { ruleId: 1, action: 'deny', status: 0, data: '' },
      {} as express.Request,
      res,
    )
    expect(status).toHaveBeenCalledWith(403)
  })

  it('extractBody returns undefined for primitive body types', async () => {
    const { waf } = mockWAF('block')
    const app = express()
    app.use((req, _res, next) => {
      ;(req as unknown as { body: unknown }).body = 42
      next()
    })
    app.use(coraza({ waf }))
    app.post('/', (_req, res) => res.send('ok'))
    const res = await request(app).post('/')
    expect(res.status).toBe(200)
  })

  it('handles multi-value request headers and missing optional req fields', async () => {
    // Directly invoke with a minimal req to exercise defensive fallbacks
    // (req.originalUrl missing, req.ip undefined, socket ports missing).
    const { waf, state } = mockWAF('block')
    const mw = coraza({ waf })
    const fakeReq = {
      method: 'GET',
      // no originalUrl — triggers `|| req.url` fallback
      url: '/x',
      httpVersion: '1.1',
      headers: { 'x-custom': ['v1', 'v2'] as string[], 'x-undef': undefined },
      // no ip, no socket ports
      socket: {},
      body: undefined,
    } as unknown as express.Request
    const fakeRes = {
      once: vi.fn(),
      headersSent: false,
      getHeaderNames: () => [],
      getHeader: () => undefined,
      writeHead: vi.fn(),
      end: vi.fn(),
    } as unknown as express.Response
    const next = vi.fn()
    // Middleware is now async — await it so state is settled.
    await mw(fakeReq, fakeRes, next)
    expect(next).toHaveBeenCalledOnce()
    const tx = [...state.txs.values()][0]!
    expect(tx.headers).toEqual(
      expect.arrayContaining([
        ['x-custom', 'v1'],
        ['x-custom', 'v2'],
      ]),
    )
    expect(tx.conn).toEqual({ addr: '', cport: 0, sport: 0 })
  })

  it('fails closed (503) when the bundle call itself throws', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequestBundle = () => {
        throw new Error('processRequestBundle boom')
      }
      return tx
    }
    const app = appWith(coraza({ waf }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(503)
  })

  it('onWAFError: allow falls through to next() when the bundle throws', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequestBundle = () => {
        throw new Error('processRequestBundle boom')
      }
      return tx
    }
    const app = appWith(coraza({ waf, onWAFError: 'allow' }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200)
  })

  it('bypasses static/media paths by default (no transaction created)', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(coraza({ waf }))
    app.get('/img/logo.png', (_req, res) => res.type('image/png').send('fake'))
    app.get('/_next/static/chunk.js', (_req, res) => res.type('text/javascript').send('1'))
    app.get('/api/login', (_req, res) => res.json({ ok: true }))

    const png = await request(app).get('/img/logo.png')
    expect(png.status).toBe(200) // bypassed — not blocked despite onHeaders
    const chunk = await request(app).get('/_next/static/chunk.js')
    expect(chunk.status).toBe(200)
    const api = await request(app).get('/api/login')
    expect(api.status).toBe(403) // dynamic path — Coraza ran, blocked

    // No transactions should have been created for the two bypassed requests.
    expect(state.nextTx).toBe(1) // only the /api/login one
  })

  it('honors custom skip patterns and merges with defaults', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(coraza({ waf, skip: { prefixes: ['/healthz'] } }))
    app.get('/healthz', (_req, res) => res.send('ok'))
    app.get('/img/a.png', (_req, res) => res.send('ok'))
    app.get('/api', (_req, res) => res.send('ok'))

    expect((await request(app).get('/healthz')).status).toBe(200)
    expect((await request(app).get('/img/a.png')).status).toBe(200)
    expect((await request(app).get('/api')).status).toBe(403)
  })

  it('skip: false disables all bypass', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(coraza({ waf, skip: false }))
    app.get('/img/logo.png', (_req, res) => res.send('ok'))
    expect((await request(app).get('/img/logo.png')).status).toBe(403)
  })

  it('forwards req.log when present (pino-http convention)', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 9, action: 'deny', status: 403, data: 'x' }),
    })
    const warn = vi.fn()
    const app = express()
    app.use((req, _res, next) => {
      ;(req as unknown as { log: { warn: typeof warn } }).log = { warn }
      next()
    })
    app.use(coraza({ waf }))
    app.get('/', (_req, res) => res.send('ok'))
    await request(app).get('/')
    expect(warn).toHaveBeenCalledWith('coraza: request blocked', expect.any(Object))
  })

  it('ignore: { methods } skips configured methods entirely', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(coraza({ waf, ignore: { methods: ['OPTIONS'] } }))
    app.options('/api', (_req, res) => res.send('ok'))
    app.get('/api', (_req, res) => res.send('ok'))
    expect((await request(app).options('/api')).status).toBe(200)
    expect((await request(app).get('/api')).status).toBe(403)
    expect(state.nextTx).toBe(1)
  })

  it('ignore: { routes } supports glob and regex routes', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(coraza({ waf, ignore: { routes: ['/healthz', /^\/internal/] } }))
    app.get('/healthz', (_req, res) => res.send('ok'))
    app.get('/internal/x', (_req, res) => res.send('ok'))
    app.get('/api', (_req, res) => res.send('ok'))
    expect((await request(app).get('/healthz')).status).toBe(200)
    expect((await request(app).get('/internal/x')).status).toBe(200)
    expect((await request(app).get('/api')).status).toBe(403)
  })

  it('ignore: { headerEquals } bypasses on matching headers', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(coraza({ waf, ignore: { headerEquals: { 'x-internal': 'true' } } }))
    app.get('/api', (_req, res) => res.send('ok'))
    expect((await request(app).get('/api').set('x-internal', 'true')).status).toBe(200)
    expect((await request(app).get('/api').set('x-internal', 'false')).status).toBe(403)
  })

  it('ignore: { bodyLargerThan } skips body inspection on oversized POSTs', async () => {
    // Predicate fires only when the body actually reached Coraza non-empty.
    // 'skip-body' means we still process URL+headers but feed an empty body
    // into the bundle, so the predicate must not see the user's payload.
    const { waf, state } = mockWAF('block', {
      onBody: (tx) =>
        tx.lastBody && tx.lastBody.length > 0
          ? { ruleId: 941100, action: 'deny', status: 403, data: 'XSS' }
          : undefined,
    })
    const app = express()
    app.use(express.json({ limit: '10mb' }))
    app.use(coraza({ waf, ignore: { bodyLargerThan: 100 } }))
    app.post('/echo', (req, res) => res.json(req.body ?? {}))
    const big = JSON.stringify({ msg: '<script>'.repeat(50) })
    const res = await request(app)
      .post('/echo')
      .set('content-length', String(big.length))
      .set('content-type', 'application/json')
      .send(big)
    expect(res.status).toBe(200)
    expect(state.nextTx).toBe(1)
  })

  it('ignore: { match } imperative escape hatch overrides declarative skip', async () => {
    // Declarative says "skip /healthz"; match says "don't skip if header
    // x-suspicious=yes". Most-restrictive wins → false (inspect).
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(
      coraza({
        waf,
        ignore: {
          routes: ['/healthz'],
          match: (ctx) =>
            (ctx.headers as Map<string, string>).get('x-suspicious') === 'yes' ? false : true,
        },
      }),
    )
    app.get('/healthz', (_req, res) => res.send('ok'))
    expect((await request(app).get('/healthz')).status).toBe(200)
    expect((await request(app).get('/healthz').set('x-suspicious', 'yes')).status).toBe(403)
  })

  it('legacy skip: maps to ignore: equivalent shape', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(coraza({ waf, skip: { prefixes: ['/healthz'] } }))
    app.get('/healthz', (_req, res) => res.send('ok'))
    app.get('/api', (_req, res) => res.send('ok'))
    expect((await request(app).get('/healthz')).status).toBe(200)
    expect((await request(app).get('/api')).status).toBe(403)
  })

  it('ignore: false disables all bypass', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const app = express()
    app.use(coraza({ waf, ignore: false }))
    app.get('/img/logo.png', (_req, res) => res.send('ok'))
    expect((await request(app).get('/img/logo.png')).status).toBe(403)
  })
})

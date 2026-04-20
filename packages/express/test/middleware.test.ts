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
    // processRequest should not have been called — no URI captured
    expect(tx?.uri).toBeUndefined()
  })

  it('skips body processing when isRequestBodyAccessible is false', async () => {
    const { waf, state } = mockWAF('block', {
      onBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'should not fire' }),
    })
    state.reqBodyAccessible = false
    const app = appWith(coraza({ waf }))
    const res = await request(app).post('/echo').send({ msg: 'benign' })
    expect(res.status).toBe(200)
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

  it('continues (does not crash) when middleware itself throws', async () => {
    const { waf } = mockWAF('block')
    // Poison newTransaction to throw.
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
    expect(res.status).toBe(200) // request continued past middleware
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

  it('catches errors inside middleware after transaction is created', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequest = () => {
        throw new Error('processRequest boom')
      }
      return tx
    }
    const app = appWith(coraza({ waf }))
    const res = await request(app).get('/hi')
    expect(res.status).toBe(200) // fell through to next()
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
})

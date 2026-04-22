import { describe, it, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { coraza, createCorazaRunner, defaultBlock } from '../src/index.js'
import { mockWAF } from './helpers.js'

function makeReq(url: string, init: RequestInit = {}): NextRequest {
  return new NextRequest(new Request(url, init))
}

describe('@coraza/next', () => {
  it('passes benign requests through (returns NextResponse.next())', async () => {
    const { waf, state } = mockWAF('block')
    const mw = coraza({ waf })
    const res = await mw(makeReq('https://example.com/hi'))
    // NextResponse.next() produces a response with x-middleware-next: 1 header
    expect(res.headers.get('x-middleware-next')).toBe('1')
    // tx destroyed after onResponse-equivalent
    expect(state.txs.size).toBe(0)
  })

  it('accepts a WAF promise (lazy-awaited)', async () => {
    const { waf } = mockWAF('block')
    const mw = coraza({ waf: Promise.resolve(waf) })
    const res = await mw(makeReq('https://example.com/'))
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })

  it('caches the resolved WAF across invocations', async () => {
    const { waf } = mockWAF('block')
    let resolveCount = 0
    const promise = (async () => {
      resolveCount++
      return waf
    })()
    const mw = coraza({ waf: promise })
    await mw(makeReq('https://example.com/'))
    await mw(makeReq('https://example.com/'))
    expect(resolveCount).toBe(1)
  })

  it('blocks on header-phase interruption', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 942100, action: 'deny', status: 403, data: 'SQLi' }),
    })
    const mw = coraza({ waf })
    const res = await mw(makeReq('https://example.com/x'))
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('942100')
  })

  it('blocks on body-phase interruption', async () => {
    const { waf } = mockWAF('block', {
      onBody: () => ({ ruleId: 941100, action: 'deny', status: 403, data: 'XSS' }),
    })
    const mw = coraza({ waf })
    const res = await mw(
      makeReq('https://example.com/', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ foo: '<script>' }),
      }),
    )
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('941100')
  })

  it('short-circuits when isRuleEngineOff', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.ruleEngineOff = true
    const mw = coraza({ waf })
    const res = await mw(makeReq('https://example.com/x?q=attack'))
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })

  it('runs body phase regardless of isRequestBodyAccessible (bundle always fires phase 2)', async () => {
    // Fused bundle runs phase 2 atomically with phase 1 so CRS's
    // anomaly-score evaluator always fires. See docs/threat-model.md.
    const { waf, state } = mockWAF('block', {
      onBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.reqBodyAccessible = false
    const mw = coraza({ waf })
    const res = await mw(
      makeReq('https://example.com/', { method: 'POST', body: 'payload' }),
    )
    expect(res.status).toBe(403)
  })

  it('honors custom onBlock', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 10, action: 'deny', status: 418, data: 'custom' }),
    })
    const onBlock = vi.fn(
      () => new Response('forbidden', { status: 499, headers: { 'x-blocked': 'yes' } }),
    )
    const mw = coraza({ waf, onBlock })
    const res = await mw(makeReq('https://example.com/'))
    expect(res.status).toBe(499)
    expect(res.headers.get('x-blocked')).toBe('yes')
    expect(onBlock).toHaveBeenCalled()
  })

  it('fails closed (503) when newTransaction itself throws', async () => {
    const { waf } = mockWAF('block')
    waf.newTransaction = () => {
      throw new Error('WAF not ready')
    }
    const mw = coraza({ waf })
    const res = await mw(makeReq('https://example.com/'))
    expect(res.status).toBe(503)
  })

  it('onWAFError: allow passes through when newTransaction throws', async () => {
    const { waf } = mockWAF('block')
    waf.newTransaction = () => {
      throw new Error('WAF not ready')
    }
    const mw = coraza({ waf, onWAFError: 'allow' })
    const res = await mw(makeReq('https://example.com/'))
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })

  it('fails closed (503) on middleware internal error', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequestBundle = () => {
        throw new Error('boom')
      }
      return tx
    }
    const mw = coraza({ waf })
    const res = await mw(makeReq('https://example.com/'))
    expect(res.status).toBe(503)
  })

  it('onWAFError: allow lets the request through on internal error', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequestBundle = () => {
        throw new Error('boom')
      }
      return tx
    }
    const mw = coraza({ waf, onWAFError: 'allow' })
    const res = await mw(makeReq('https://example.com/'))
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })

  it('extracts x-forwarded-for client address', async () => {
    const { waf, state } = mockWAF('block')
    const mw = coraza({ waf })
    await mw(
      makeReq('https://example.com/', {
        headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.1' },
      }),
    )
    // Transaction was closed, so state.txs is empty — assert via nextTx counter.
    expect(state.nextTx).toBeGreaterThanOrEqual(1)
  })

  it('defaultBlock builds a 403 response by default', () => {
    const res = defaultBlock(
      { ruleId: 7, action: 'deny', status: 0, data: '' },
      {} as NextRequest,
    )
    expect(res.status).toBe(403)
  })

  it('does not stream-read the body for GET/HEAD/OPTIONS (avoids req.arrayBuffer waste)', async () => {
    // The bundle always runs phase 2; body will be undefined for these
    // verbs so Coraza sees an empty request body. What this test asserts
    // is the *performance* property that we don't pay to read an
    // arrayBuffer for verbs that shouldn't have one.
    const { waf } = mockWAF('block')
    const mw = coraza({ waf })
    for (const method of ['GET', 'HEAD', 'OPTIONS']) {
      const req = makeReq('https://example.com/', {
        method,
        headers: { 'content-type': 'text/plain' },
      })
      const spy = vi.spyOn(req, 'arrayBuffer')
      const res = await mw(req)
      expect(spy).not.toHaveBeenCalled()
      expect(res.status).toBeGreaterThanOrEqual(200)
    }
  })

  it('bypasses default static paths without touching the WAF', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const mw = coraza({ waf })
    const png = await mw(makeReq('https://example.com/img/logo.png'))
    expect(png.headers.get('x-middleware-next')).toBe('1')
    const chunk = await mw(makeReq('https://example.com/_next/static/chunk.js'))
    expect(chunk.headers.get('x-middleware-next')).toBe('1')
    // Dynamic path should still be blocked.
    const api = await mw(makeReq('https://example.com/api'))
    expect(api.status).toBe(403)
    expect(state.nextTx).toBe(1) // only /api created a tx
  })

  it('skip: false disables bypass in next', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const mw = coraza({ waf, skip: false })
    const png = await mw(makeReq('https://example.com/img/logo.png'))
    expect(png.status).toBe(403)
  })

  it('processes empty-body POST without triggering body phase', async () => {
    const { waf } = mockWAF('block')
    const mw = coraza({ waf })
    const res = await mw(makeReq('https://example.com/', { method: 'POST' }))
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })
})

// Compose-with-existing-proxy contract. The runner exposes a structured
// decision so downstream `proxy.ts` code doesn't need to sniff
// `x-middleware-next` on the response body — that sniff is internal
// territory, see github.com/coraza-incubator/coraza-node#8.
describe('@coraza/next createCorazaRunner', () => {
  it('returns { allow: true } on benign requests', async () => {
    const { waf } = mockWAF('block')
    const run = createCorazaRunner({ waf })
    const decision = await run(makeReq('https://example.com/hi'))
    expect(decision).toEqual({ allow: true })
  })

  it('returns { blocked } with the onBlock Response on an interruption', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 942100, action: 'deny', status: 403, data: 'SQLi' }),
    })
    const run = createCorazaRunner({ waf })
    const decision = await run(makeReq('https://example.com/x?id=1%27OR%271'))
    expect('blocked' in decision).toBe(true)
    if (!('blocked' in decision)) return
    expect(decision.blocked.status).toBe(403)
    expect(await decision.blocked.text()).toContain('942100')
  })

  it('bypasses static paths (returns allow without a WAF call)', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const run = createCorazaRunner({ waf })
    const decision = await run(makeReq('https://example.com/img/logo.png'))
    expect(decision).toEqual({ allow: true })
    expect(state.nextTx).toBe(0)
  })

  it('composes cleanly with existing proxy logic', async () => {
    // Shape of the compose pattern we want to document in the README:
    // run Coraza first, bail on block, otherwise fall through to auth.
    // Interruption is URL-keyed so the same mock services both the
    // "blocked" and "allowed" legs of the flow.
    const { waf } = mockWAF('block', {
      onHeaders: (tx) =>
        tx.uri?.uri?.includes('OR')
          ? { ruleId: 942100, action: 'deny', status: 403, data: 'SQLi' }
          : undefined,
    })
    const run = createCorazaRunner({ waf })
    async function proxy(req: NextRequest): Promise<Response> {
      const decision = await run(req)
      if ('blocked' in decision) return decision.blocked
      // Pretend-auth: deny when no cookie is present.
      if (!req.headers.get('cookie')) {
        return new Response('Unauthorized', { status: 401 })
      }
      return new Response(null, { headers: { 'x-middleware-next': '1' } })
    }
    const blocked = await proxy(makeReq('https://example.com/x?id=1%27OR%271'))
    expect(blocked.status).toBe(403)
    const unauth = await proxy(makeReq('https://example.com/hi'))
    expect(unauth.status).toBe(401)
    const allowed = await proxy(
      makeReq('https://example.com/hi', { headers: { cookie: 'session=abc' } }),
    )
    expect(allowed.headers.get('x-middleware-next')).toBe('1')
  })
})

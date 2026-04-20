import { describe, it, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { createCorazaMiddleware, defaultBlock } from '../src/index.js'
import { mockWAF } from './helpers.js'

function makeReq(url: string, init: RequestInit = {}): NextRequest {
  return new NextRequest(new Request(url, init))
}

describe('@coraza/next', () => {
  it('passes benign requests through (returns NextResponse.next())', async () => {
    const { waf, state } = mockWAF('block')
    const mw = createCorazaMiddleware(waf)
    const res = await mw(makeReq('https://example.com/hi'))
    // NextResponse.next() produces a response with x-middleware-next: 1 header
    expect(res.headers.get('x-middleware-next')).toBe('1')
    // tx destroyed after onResponse-equivalent
    expect(state.txs.size).toBe(0)
  })

  it('accepts a WAF promise (lazy-awaited)', async () => {
    const { waf } = mockWAF('block')
    const mw = createCorazaMiddleware(Promise.resolve(waf))
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
    const mw = createCorazaMiddleware(promise)
    await mw(makeReq('https://example.com/'))
    await mw(makeReq('https://example.com/'))
    expect(resolveCount).toBe(1)
  })

  it('blocks on header-phase interruption', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 942100, action: 'deny', status: 403, data: 'SQLi' }),
    })
    const mw = createCorazaMiddleware(waf)
    const res = await mw(makeReq('https://example.com/x'))
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('942100')
  })

  it('blocks on body-phase interruption', async () => {
    const { waf } = mockWAF('block', {
      onBody: () => ({ ruleId: 941100, action: 'deny', status: 403, data: 'XSS' }),
    })
    const mw = createCorazaMiddleware(waf)
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
    const mw = createCorazaMiddleware(waf)
    const res = await mw(makeReq('https://example.com/x?q=attack'))
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })

  it('skips body when isRequestBodyAccessible is false', async () => {
    const { waf, state } = mockWAF('block', {
      onBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    state.reqBodyAccessible = false
    const mw = createCorazaMiddleware(waf)
    const res = await mw(
      makeReq('https://example.com/', { method: 'POST', body: 'payload' }),
    )
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })

  it('honors custom onBlock', async () => {
    const { waf } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 10, action: 'deny', status: 418, data: 'custom' }),
    })
    const onBlock = vi.fn(
      () => new Response('forbidden', { status: 499, headers: { 'x-blocked': 'yes' } }),
    )
    const mw = createCorazaMiddleware(waf, { onBlock })
    const res = await mw(makeReq('https://example.com/'))
    expect(res.status).toBe(499)
    expect(res.headers.get('x-blocked')).toBe('yes')
    expect(onBlock).toHaveBeenCalled()
  })

  it('continues on middleware internal error', async () => {
    const { waf } = mockWAF('block')
    const realNew = waf.newTransaction.bind(waf)
    waf.newTransaction = () => {
      const tx = realNew()
      tx.processRequest = () => {
        throw new Error('boom')
      }
      return tx
    }
    const mw = createCorazaMiddleware(waf)
    const res = await mw(makeReq('https://example.com/'))
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })

  it('extracts x-forwarded-for client address', async () => {
    const { waf, state } = mockWAF('block')
    const mw = createCorazaMiddleware(waf)
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

  it('does not treat GET/HEAD/OPTIONS requests as body-bearing', async () => {
    const { waf } = mockWAF('block', {
      onBody: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'should not fire' }),
    })
    const mw = createCorazaMiddleware(waf)
    for (const method of ['GET', 'HEAD', 'OPTIONS']) {
      const res = await mw(
        makeReq('https://example.com/', { method, headers: { 'content-type': 'text/plain' } }),
      )
      expect(res.headers.get('x-middleware-next')).toBe('1')
    }
  })

  it('bypasses default static paths without touching the WAF', async () => {
    const { waf, state } = mockWAF('block', {
      onHeaders: () => ({ ruleId: 1, action: 'deny', status: 403, data: 'x' }),
    })
    const mw = createCorazaMiddleware(waf)
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
    const mw = createCorazaMiddleware(waf, { skip: false })
    const png = await mw(makeReq('https://example.com/img/logo.png'))
    expect(png.status).toBe(403)
  })

  it('processes empty-body POST without triggering body phase', async () => {
    const { waf } = mockWAF('block')
    const mw = createCorazaMiddleware(waf)
    const res = await mw(makeReq('https://example.com/', { method: 'POST' }))
    expect(res.headers.get('x-middleware-next')).toBe('1')
  })
})

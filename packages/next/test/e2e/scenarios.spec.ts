import { test, expect } from '@playwright/test'

test.describe('@coraza/next E2E', () => {
  test('1. benign request passes through (200)', async ({ request }) => {
    const res = await request.get('/')
    expect(res.status()).toBe(200)
  })

  test('2. SQLi in query string is blocked', async ({ request }) => {
    const res = await request.get("/?q=' OR 1=1--")
    expect(res.status()).toBeGreaterThanOrEqual(400)
  })

  test('3. XSS payload in JSON body is blocked', async ({ request }) => {
    const res = await request.post('/api/echo', {
      data: { msg: '<script>alert(1)</script>' },
    })
    expect(res.status()).toBeGreaterThanOrEqual(400)
  })

  test('4. large body is handled without OOM', async ({ request }) => {
    const big = 'x'.repeat(100_000)
    const res = await request.post('/api/echo', { data: { big } })
    expect([200, 413, 403].includes(res.status())).toBe(true)
  })

})

// Not in this E2E: custom onBlock override (unit-tested in test/middleware.test.ts)
// and detect-mode passthrough (a Coraza-internal toggle, not adapter logic —
// verified in packages/core/test/wafCreate.test.ts).

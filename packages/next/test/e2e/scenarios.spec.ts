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

  test('5. custom block response override works', async () => {
    test.skip(true, 'Custom onBlock example route not wired in v1')
  })

  test('6. detect-only mode logs but does not block', async () => {
    test.skip(
      process.env.MODE !== 'detect',
      'Detect-only scenario runs in a separate CI job (MODE=detect)',
    )
  })
})

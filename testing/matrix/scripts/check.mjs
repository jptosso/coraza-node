#!/usr/bin/env node
// testing/matrix/scripts/check.mjs — the single invariant driver every
// matrix leg runs against a booted case.
//
// Contract (every case must honour):
//
//   GET  /healthz            → 200 (any body)
//   GET  /search?q=hello     → 200                 (benign)
//   GET  /search?q=<SQLi>    → 403                 (query-string SQLi)
//   POST /echo { msg: XSS }  → 403                 (JSON body XSS)
//
// Env:
//   CASE_PORT     port the case server is bound to (required)
//   CASE_HOST     hostname (default 127.0.0.1)
//   CASE_NAME     label for log lines (default "case")
//   BOOT_TIMEOUT  seconds to wait for /healthz (default 45)
//
// Exit codes:
//   0  — all four assertions passed
//   1  — one or more assertions failed (see stderr for a diff)
//   2  — the case never became ready within BOOT_TIMEOUT

const HOST = process.env.CASE_HOST || '127.0.0.1'
const PORT = Number(process.env.CASE_PORT || 0)
const NAME = process.env.CASE_NAME || 'case'
const BOOT_TIMEOUT = Number(process.env.BOOT_TIMEOUT || 45)

if (!PORT) {
  process.stderr.write('check.mjs: CASE_PORT is required\n')
  process.exit(2)
}

const base = `http://${HOST}:${PORT}`

const SQLI = "'+OR+1=1--"
const XSS = '<script>alert(1)</script>'

async function waitForReady() {
  const deadline = Date.now() + BOOT_TIMEOUT * 1000
  let lastErr = ''
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${base}/healthz`, { signal: AbortSignal.timeout(2000) })
      if (res.status === 200) return
      lastErr = `HTTP ${res.status}`
    } catch (err) {
      lastErr = err.message || String(err)
    }
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error(`[${NAME}] /healthz not ready after ${BOOT_TIMEOUT}s (last=${lastErr})`)
}

async function scenario(label, method, path, body, expectStatus) {
  const init = { method, signal: AbortSignal.timeout(10_000) }
  if (body !== undefined) {
    init.headers = { 'content-type': 'application/json' }
    init.body = JSON.stringify(body)
  }
  const res = await fetch(`${base}${path}`, init).catch((err) => {
    throw new Error(`[${NAME}] ${label}: transport error — ${err.message || err}`)
  })
  // Drain the body so the server can shut down cleanly.
  await res.text().catch(() => '')
  if (res.status !== expectStatus) {
    return {
      label,
      ok: false,
      actual: res.status,
      expected: expectStatus,
    }
  }
  return { label, ok: true, actual: res.status, expected: expectStatus }
}

async function main() {
  try {
    await waitForReady()
  } catch (err) {
    process.stderr.write(`${err.message}\n`)
    process.exit(2)
  }

  const results = []
  results.push(await scenario('benign-search', 'GET', '/search?q=hello', undefined, 200))
  results.push(
    await scenario(
      'sqli-search',
      'GET',
      `/search?q=${encodeURIComponent(SQLI)}`,
      undefined,
      403,
    ),
  )
  results.push(await scenario('xss-echo', 'POST', '/echo', { msg: XSS }, 403))

  const failed = results.filter((r) => !r.ok)
  const summary = results
    .map((r) => `${r.ok ? 'PASS' : 'FAIL'} ${r.label.padEnd(14)} got=${r.actual} want=${r.expected}`)
    .join('\n')
  process.stdout.write(`[${NAME}] ${process.env.CASE_LABEL || ''}\n${summary}\n`)
  if (failed.length > 0) {
    process.stderr.write(`[${NAME}] ${failed.length}/${results.length} scenario(s) failed\n`)
    process.exit(1)
  }
}

main().catch((err) => {
  process.stderr.write(`check.mjs: ${err.stack || err.message || err}\n`)
  process.exit(1)
})

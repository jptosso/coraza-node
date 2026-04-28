#!/usr/bin/env node
// testing/matrix/scripts/check.mjs — the single invariant driver every
// matrix leg runs against a booted case.
//
// Contract (every case must honour):
//
//   GET  /healthz                              → 200 (any body)
//   GET  /search?q=hello                       → 200    (benign)
//   GET  /search?q=<SQLi>                      → 403    (query-string SQLi)
//   POST /echo   { msg: XSS }       JSON       → 403    (JSON body XSS)
//   POST /echo   { q: "hello" }     JSON       → 200    (JSON benign)
//   POST /echo   { q: SQLi }        JSON       → 403    (JSON SQLi)
//   POST /form   q=hello           urlencoded  → 200    (form benign)
//   POST /form   q=<SQLi>          urlencoded  → 403    (form SQLi)
//   POST /upload <file>            multipart   → 200    (multipart benign)
//   POST /upload <file>+q=<SQLi>   multipart   → 403    (multipart SQLi field)
//
// The three "JSON / form / multipart × benign / sqli" pairs are why the
// matrix exists — they prove every adapter inspects every body shape.
//
// Env:
//   CASE_PORT     port the case server is bound to (required)
//   CASE_HOST     hostname (default 127.0.0.1)
//   CASE_NAME     label for log lines (default "case")
//   BOOT_TIMEOUT  seconds to wait for /healthz (default 45)
//
// Exit codes:
//   0  — all assertions passed
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

const SQLI = "' OR 1=1--"
const SQLI_QS = "'+OR+1=1--"
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

async function run(label, init, path, expectStatus) {
  init.signal = AbortSignal.timeout(15_000)
  const res = await fetch(`${base}${path}`, init).catch((err) => {
    throw new Error(`[${NAME}] ${label}: transport error — ${err.message || err}`)
  })
  // Drain the body so the server can shut down cleanly.
  await res.text().catch(() => '')
  return {
    label,
    ok: res.status === expectStatus,
    actual: res.status,
    expected: expectStatus,
  }
}

function jsonInit(payload) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  }
}

function formInit(query) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: query,
  }
}

// Hand-roll a multipart body so the request bytes are deterministic across
// node versions. `fetch`'s built-in FormData encoder picks a random boundary
// and orders parts in insertion order — fine, but spelling it out keeps
// the WAF-visible payload identical between runs and frameworks.
function multipartInit({ extraFields = {} } = {}) {
  const boundary = '----matrixBoundary' + Math.random().toString(36).slice(2, 10)
  const CRLF = '\r\n'
  const parts = []
  for (const [name, value] of Object.entries(extraFields)) {
    parts.push(
      `--${boundary}${CRLF}` +
        `Content-Disposition: form-data; name="${name}"${CRLF}${CRLF}` +
        `${value}${CRLF}`,
    )
  }
  parts.push(
    `--${boundary}${CRLF}` +
      `Content-Disposition: form-data; name="file"; filename="hello.txt"${CRLF}` +
      `Content-Type: text/plain${CRLF}${CRLF}` +
      `hello world${CRLF}`,
  )
  parts.push(`--${boundary}--${CRLF}`)
  const body = Buffer.from(parts.join(''), 'utf8')
  return {
    method: 'POST',
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
    body,
  }
}

async function main() {
  try {
    await waitForReady()
  } catch (err) {
    process.stderr.write(`${err.message}\n`)
    process.exit(2)
  }

  const results = []

  // GET search.
  results.push(await run('benign-search', { method: 'GET' }, '/search?q=hello', 200))
  results.push(
    await run('sqli-search', { method: 'GET' }, `/search?q=${encodeURIComponent(SQLI_QS)}`, 403),
  )

  // JSON.
  results.push(await run('xss-echo', jsonInit({ msg: XSS }), '/echo', 403))
  results.push(await run('json-benign', jsonInit({ q: 'hello' }), '/echo', 200))
  results.push(await run('json-sqli', jsonInit({ q: SQLI }), '/echo', 403))

  // urlencoded.
  results.push(await run('form-benign', formInit('q=hello'), '/form', 200))
  results.push(
    await run('form-sqli', formInit(`q=${encodeURIComponent(SQLI)}`), '/form', 403),
  )

  // multipart.
  results.push(await run('multipart-benign', multipartInit(), '/upload', 200))
  results.push(
    await run(
      'multipart-sqli',
      multipartInit({ extraFields: { q: SQLI } }),
      '/upload',
      403,
    ),
  )

  const failed = results.filter((r) => !r.ok)
  const summary = results
    .map((r) => `${r.ok ? 'PASS' : 'FAIL'} ${r.label.padEnd(18)} got=${r.actual} want=${r.expected}`)
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

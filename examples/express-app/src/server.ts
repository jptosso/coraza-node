import express from 'express'
import http from 'node:http'
import os from 'node:os'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/express'
import { ftwEcho, ftwModeEnabled, handlers } from '@coraza/example-shared'

const port = Number(process.env.PORT ?? 3001)
const ftw = ftwModeEnabled()
// FTW mode is the only time we forcibly override mode + paranoia: the
// go-ftw contract expects block-mode responses at paranoia 2. Normal
// demo traffic defaults to block at paranoia 1.
const mode = ftw ? 'block' : ((process.env.MODE ?? 'block') as 'detect' | 'block')
const wafDisabled = process.env.WAF === 'off'
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? os.availableParallelism())

const app = express()
app.use(express.json({ limit: '10mb' }))
app.use(express.raw({ type: 'application/octet-stream', limit: '10mb' }))
// FTW test requests arrive with many content-types (x-www-form-urlencoded,
// text/xml, application/soap+xml, …). Accept any body as raw bytes when
// FTW=1 so CRS evaluates the exact payload the test case sent.
if (ftw) app.use(express.raw({ type: '*/*', limit: '10mb' }))

if (!wafDisabled) {
  const rules = recommended(ftw ? { paranoia: 2 } : {})
  const waf = usePool
    ? await createWAFPool({ rules, mode, size: poolSize })
    : await createWAF({ rules, mode })
  app.use(coraza({ waf, inspectResponse: ftw }))
  console.log(
    `express :${port} waf=on mode=${mode} ${usePool ? `POOL size=${poolSize}` : 'single'}${ftw ? ' FTW=1 paranoia=2' : ''}`,
  )
} else {
  console.log(`express :${port} waf=off`)
}

if (ftw) {
  // Single catch-all that echoes everything back. Mount before the named
  // demo routes so FTW traffic always hits the same handler regardless
  // of the test case's target URL. The `/{*any}` form (optional wildcard)
  // is required in Express 5 / path-to-regexp v8: plain `/*any` only
  // matches one-or-more segments, so GET `/` silently fell through to
  // Express's finalhandler 404 — which then broke the FTW health probe
  // (it only accepted 200/403) and masked the server as "not listening".
  app.all('/{*any}', (req, res) => {
    const headers: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === 'string') headers[k] = v
      else if (Array.isArray(v)) headers[k] = v.join(',')
    }
    const body = Buffer.isBuffer(req.body)
      ? req.body.toString('utf8')
      : typeof req.body === 'string'
        ? req.body
        : JSON.stringify(req.body ?? '')
    const r = ftwEcho({ method: req.method, url: req.originalUrl, headers, body })
    res.status(r.status).type(r.contentType).send(JSON.stringify(r.body))
  })
} else {
  app.get('/', (_req, res) => res.json(handlers.root('express').body))
  app.get('/healthz', (_req, res) =>
    res.type('text/plain').send(handlers.healthz().body as string),
  )
  app.get('/search', (req, res) =>
    res.json(handlers.search(req.query.q as string | undefined).body),
  )
  app.post('/echo', (req, res) => res.json(handlers.echo(req.body).body))
  app.post('/upload', (req, res) => {
    const len = Buffer.isBuffer(req.body)
      ? req.body.length
      : JSON.stringify(req.body ?? '').length
    res.json(handlers.upload(len).body)
  })
  app.get('/img/logo.png', (_req, res) => {
    const r = handlers.image()
    res.type(r.contentType!).send(r.body as Buffer)
  })
  app.get('/api/users/:id', (req, res) =>
    res.json(handlers.user(req.params.id!).body),
  )
}

// Bind on the IPv4 wildcard so go-ftw's `127.0.0.1` probe always matches
// regardless of the host's v4/v6 preference. Use
// `http.createServer(app).listen(...)` directly rather than Express 5's
// `app.listen(...)` — the latter is a thin wrapper whose shape shifts
// with the args passed and is harder to reason about when debugging.
process.stderr.write(`[${new Date().toISOString()}] express calling listen()\n`)
const server = http.createServer(app)
server.listen(port, '0.0.0.0', () => {
  const addr = server.address()
  process.stderr.write(
    `[${new Date().toISOString()}] express listen callback fired; address=${JSON.stringify(addr)}\n`,
  )
})
server.on('error', (err: unknown) => {
  process.stderr.write(`express listen error: ${(err as Error).message}\n`)
})
// Under FTW mode the CRS corpus sends CONNECT requests (920100-4..6).
// Node's http.Server closes the socket when no `connect` listener is
// registered, which go-ftw surfaces as `unexpected EOF` and treats as
// a hard error — aborting the whole run. Respond with 501 so go-ftw
// reads a proper HTTP line and carries on to the next test. The adapter
// controller mounted above never sees CONNECT because it never reaches
// Express's `request` dispatch; the WAF never sees it either, which is
// fine — CONNECT isn't a phase-1 attack surface we enforce.
if (ftw) {
  server.on('connect', (_req, socket) => {
    socket.write('HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    socket.end()
  })
}
// Keep a handler around so SIGTERM shows up in stderr too — makes the
// "when did we exit" question answerable from the artifact alone.
process.on('SIGTERM', () => {
  process.stderr.write('express caught SIGTERM, closing\n')
  server.close(() => process.exit(0))
})

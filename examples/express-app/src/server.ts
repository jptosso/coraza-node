import express from 'express'
import http from 'node:http'
import path from 'node:path'
import fs from 'node:fs'
import os from 'node:os'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import multer from 'multer'
import { createWAF, createWAFPool } from '@coraza/core'
import type { AnyWAF } from '@coraza/core'
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
// urlencoded: lets the WAF inspect form-encoded `q=...` payloads. Limit kept
// modest so demo posts don't accidentally amplify into pathological CRS work.
app.use(express.urlencoded({ extended: true, limit: '1mb' }))
app.use(express.raw({ type: 'application/octet-stream', limit: '10mb' }))
// Buffer multipart bodies as a raw Buffer on `req.body` so Coraza's
// adapter sees the literal bytes (with `Content-Disposition` filename
// attribute). Without this the multer route below would consume the
// stream first and Coraza would see no body at all. The /upload handler
// re-parses this buffer with multer via a synthetic stream.
app.use(express.raw({ type: 'multipart/form-data', limit: '10mb' }))
// FTW test requests arrive with many content-types (x-www-form-urlencoded,
// text/xml, application/soap+xml, …). Accept any body as raw bytes when
// FTW=1 so CRS evaluates the exact payload the test case sent.
if (ftw) app.use(express.raw({ type: '*/*', limit: '10mb' }))

// Multer: in-memory diskless storage so /upload echoes filename + length
// without ever touching disk. Coraza's middleware sees the raw multipart
// body via the Express request stream because it runs *before* multer
// (multer is mounted only on the /upload route below).
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } })

if (!wafDisabled) {
  // CRS's `crs-setup.conf.example` ships rules 900200/900220 commented out
  // by default, so `tx.allowed_request_content_type` is empty and rule
  // 920420 "Request content type is not allowed by policy" fires on
  // every body-bearing request — even benign JSON. Combined with rule
  // 920350 firing on numeric-IP hosts (which is unavoidable on
  // localhost) and 922110 firing on Coraza's internally-rebuilt
  // multipart Content-Type, the score reaches the 949110 threshold of
  // 5 on every POST and the demo can't show the benign-vs-malicious
  // split clearly. We disable these three for the demo so genuine
  // attack patterns (SQLi/XSS/path-traversal in args + body content)
  // are what trips the WAF.
  const crsTuning = [
    'SecRuleRemoveById 920420',
    'SecRuleRemoveById 920350',
    'SecRuleRemoveById 922110',
  ].join('\n')
  const rules = recommended(
    ftw ? { paranoia: 2 } : { extra: crsTuning },
  )
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
  // JSON echo (large bodies allowed: express.json above is 10 MB).
  app.post('/echo', (req, res) => res.json(handlers.echo(req.body).body))
  // application/x-www-form-urlencoded — express.urlencoded parses into req.body
  // before this handler runs; the WAF middleware has already inspected the
  // raw bytes by then because coraza() runs first in the chain.
  app.post('/form', (req, res) => {
    res.json({ received: req.body })
  })
  // multipart/form-data — Coraza has already inspected the raw multipart
  // bytes (buffered onto `req.body` by the express.raw middleware above)
  // and either blocked or let it through. By the time we reach this
  // handler, `req.body` is a Buffer for multipart and we feed multer
  // a synthetic stream that re-emits the same bytes. For
  // application/octet-stream bench traffic the body is also a Buffer
  // (different express.raw middleware) and we fall back to the legacy
  // byte-length echo so existing bench scenarios keep working. multer
  // uses memoryStorage — files never touch disk.
  app.post('/upload', (req, res, next) => {
    if (req.is('multipart/form-data') && Buffer.isBuffer(req.body)) {
      const buf = req.body
      // Synthetic readable that emits the buffered bytes; multer reads
      // from this just like it would from the raw socket stream.
      const synthetic = Readable.from([buf]) as unknown as express.Request
      Object.assign(synthetic, {
        headers: req.headers,
        url: req.url,
        method: req.method,
        socket: req.socket,
      })
      // Hand off req.body so multer doesn't see it as already-parsed.
      delete (req as { body?: unknown }).body
      upload.any()(
        synthetic as unknown as express.Request,
        res,
        (err?: unknown) => {
          if (err) return next(err)
          const sBody = (synthetic as unknown as { body?: unknown }).body
          const sFiles =
            ((synthetic as unknown as { files?: Express.Multer.File[] }).files) ?? []
          res.json({
            fields: Object.keys((sBody as Record<string, unknown>) ?? {}),
            files: sFiles.map((f) => ({
              name: f.originalname,
              bytes: f.size,
              field: f.fieldname,
            })),
          })
        },
      )
      return
    }
    const len = Buffer.isBuffer(req.body)
      ? req.body.length
      : JSON.stringify(req.body ?? '').length
    res.json(handlers.upload(len).body)
  })
  // Static download. Path param :name is attacker-controlled — the WAF runs
  // first and CRS path-traversal rules (e.g. 930100..930120) catch
  // `/download/../../etc/passwd` before this handler is reached. We still
  // resolve + scope-check defensively so a future WAF bypass doesn't escape
  // the public dir.
  const here = path.dirname(fileURLToPath(import.meta.url))
  const publicDir = path.resolve(here, '..', 'public')
  app.get('/download/:name', (req, res) => {
    const name = req.params.name!
    const resolved = path.resolve(publicDir, name)
    if (!resolved.startsWith(publicDir + path.sep)) {
      res.status(400).type('text/plain').send('bad path')
      return
    }
    if (!fs.existsSync(resolved)) {
      res.status(404).type('text/plain').send('not found')
      return
    }
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(resolved)}"`)
    fs.createReadStream(resolved).pipe(res)
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

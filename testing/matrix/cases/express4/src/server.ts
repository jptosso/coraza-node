import express from 'express'
import http from 'node:http'
import { Readable } from 'node:stream'
import multer from 'multer'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/express'

const port = Number(process.env.PORT ?? 3000)
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
// Same three-rule disable as examples/express-app: 920420 (content-type
// not in policy), 920350 (numeric-IP host on localhost), 922110 (Coraza's
// rebuilt multipart Content-Type) — without them benign body-bearing
// POSTs all 403 at PL1 and the matrix can't show benign-vs-malicious.
const crsTuning = [
  'SecRuleRemoveById 920420',
  'SecRuleRemoveById 920350',
  'SecRuleRemoveById 922110',
].join('\n')
const rules = recommended({ extra: crsTuning })
const waf = usePool
  ? await createWAFPool({ rules, mode, size: poolSize })
  : await createWAF({ rules, mode })

const app = express()
app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: true, limit: '1mb' }))
app.use(express.raw({ type: 'multipart/form-data', limit: '5mb' }))
app.use(coraza({ waf }))

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } })

app.get('/healthz', (_req, res) => {
  res.status(200).type('text/plain').send('ok')
})
app.get('/', (_req, res) => {
  res.status(200).json({ ok: true })
})
app.get('/search', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : ''
  res.status(200).json({ q, len: q.length })
})
app.post('/echo', (req, res) => {
  res.status(200).json(req.body ?? {})
})
app.post('/form', (req, res) => {
  res.status(200).json({ received: req.body })
})
app.post('/upload', (req, res, next) => {
  if (!req.is('multipart/form-data') || !Buffer.isBuffer(req.body)) {
    res.status(400).json({ error: 'expected multipart/form-data' })
    return
  }
  const synthetic = Readable.from([req.body]) as unknown as express.Request
  Object.assign(synthetic, {
    headers: req.headers,
    url: req.url,
    method: req.method,
    socket: req.socket,
  })
  delete (req as { body?: unknown }).body
  upload.any()(synthetic as unknown as express.Request, res, (err?: unknown) => {
    if (err) return next(err)
    const sBody = (synthetic as unknown as { body?: Record<string, unknown> }).body ?? {}
    const sFiles = (synthetic as unknown as { files?: Express.Multer.File[] }).files ?? []
    res.status(200).json({
      fields: Object.keys(sBody),
      files: sFiles.map((f) => ({
        name: f.originalname,
        bytes: f.size,
        field: f.fieldname,
      })),
    })
  })
})

const server = http.createServer(app)
server.listen(port, '0.0.0.0', () => {
  process.stdout.write(`matrix-express4 listening on :${port}\n`)
})
process.on('SIGTERM', () => server.close(() => process.exit(0)))

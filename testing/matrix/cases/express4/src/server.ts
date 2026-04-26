import express from 'express'
import http from 'node:http'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/express'

const port = Number(process.env.PORT ?? 3000)
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
const rules = recommended()
const waf = usePool
  ? await createWAFPool({ rules, mode, size: poolSize })
  : await createWAF({ rules, mode })

const app = express()
app.use(express.json({ limit: '1mb' }))
app.use(coraza({ waf }))

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

const server = http.createServer(app)
server.listen(port, '0.0.0.0', () => {
  process.stdout.write(`matrix-express4 listening on :${port}\n`)
})
process.on('SIGTERM', () => server.close(() => process.exit(0)))

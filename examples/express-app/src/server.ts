import express from 'express'
import os from 'node:os'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/express'
import { handlers } from '@coraza/example-shared'

const port = Number(process.env.PORT ?? 3001)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
const wafDisabled = process.env.WAF === 'off'
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? os.availableParallelism())

const app = express()
app.use(express.json({ limit: '10mb' }))
app.use(express.raw({ type: 'application/octet-stream', limit: '10mb' }))

if (!wafDisabled) {
  const waf = usePool
    ? await createWAFPool({ rules: recommended(), mode, size: poolSize })
    : await createWAF({ rules: recommended(), mode })
  app.use(coraza({ waf }))
  console.log(
    `express :${port} waf=on mode=${mode} ${usePool ? `POOL size=${poolSize}` : 'single'}`,
  )
} else {
  console.log(`express :${port} waf=off`)
}

app.get('/', (_req, res) => res.json(handlers.root('express').body))
app.get('/healthz', (_req, res) => res.type('text/plain').send(handlers.healthz().body as string))
app.get('/search', (req, res) => res.json(handlers.search(req.query.q as string | undefined).body))
app.post('/echo', (req, res) => res.json(handlers.echo(req.body).body))
app.post('/upload', (req, res) => {
  const len = Buffer.isBuffer(req.body) ? req.body.length : JSON.stringify(req.body ?? '').length
  res.json(handlers.upload(len).body)
})
app.get('/img/logo.png', (_req, res) => {
  const r = handlers.image()
  res.type(r.contentType!).send(r.body as Buffer)
})
app.get('/api/users/:id', (req, res) => res.json(handlers.user(req.params.id!).body))

app.listen(port)

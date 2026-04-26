import Fastify from 'fastify'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/fastify'

const port = Number(process.env.PORT ?? 3000)
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
const rules = recommended()
const waf = usePool
  ? await createWAFPool({ rules, mode, size: poolSize })
  : await createWAF({ rules, mode })

const app = Fastify({ logger: false, bodyLimit: 1024 * 1024 })
await app.register(coraza, { waf })

app.get('/healthz', async (_req, reply) => {
  reply.type('text/plain')
  return 'ok'
})
app.get('/', async () => ({ ok: true }))
app.get<{ Querystring: { q?: string } }>('/search', async (req) => {
  const q = req.query.q ?? ''
  return { q, len: q.length }
})
app.post('/echo', async (req) => (req.body as unknown) ?? {})

await app.listen({ port, host: '0.0.0.0' })
process.stdout.write(`matrix-fastify5 listening on :${port}\n`)
process.on('SIGTERM', async () => {
  await app.close()
  process.exit(0)
})

import Fastify from 'fastify'
import { createWAF } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/fastify'
import { handlers } from '@coraza/example-shared'

const port = Number(process.env.PORT ?? 3002)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
const wafDisabled = process.env.WAF === 'off'

const app = Fastify({ logger: false, bodyLimit: 10 * 1024 * 1024 })

app.addContentTypeParser(
  'application/octet-stream',
  { parseAs: 'buffer' },
  (_req, body, done) => done(null, body),
)

if (!wafDisabled) {
  const waf = await createWAF({ rules: recommended(), mode })
  await app.register(coraza, { waf })
}

app.get('/', async () => handlers.root('fastify').body)
app.get('/healthz', async (_req, reply) => {
  reply.type('text/plain')
  return handlers.healthz().body
})
app.get<{ Querystring: { q?: string } }>('/search', async (req) =>
  handlers.search(req.query.q).body,
)
app.post('/echo', async (req) => handlers.echo(req.body).body)
app.post('/upload', async (req) => {
  const b = req.body
  const len = Buffer.isBuffer(b) ? b.length : JSON.stringify(b ?? '').length
  return handlers.upload(len).body
})
app.get('/img/logo.png', async (_req, reply) => {
  const r = handlers.image()
  reply.type(r.contentType!)
  return r.body
})
app.get<{ Params: { id: string } }>('/api/users/:id', async (req) =>
  handlers.user(req.params.id).body,
)

await app.listen({ port, host: '0.0.0.0' })
console.log(`fastify listening on :${port} (mode=${mode}, waf=${wafDisabled ? 'off' : 'on'})`)

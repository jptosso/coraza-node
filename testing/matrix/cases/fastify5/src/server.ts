import Fastify from 'fastify'
import formbody from '@fastify/formbody'
import Busboy from 'busboy'
import { Readable } from 'node:stream'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/fastify'

const port = Number(process.env.PORT ?? 3000)
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
// Same three-rule disable as examples/express-app — see that file for the
// full justification. Disabling 920420 / 920350 / 922110 lets benign
// body-bearing POSTs through at PL1 so the matrix can show the
// benign-vs-malicious split.
const crsTuning = [
  'SecRuleRemoveById 920420',
  'SecRuleRemoveById 920350',
  'SecRuleRemoveById 922110',
].join('\n')
const rules = recommended({ extra: crsTuning })
const waf = usePool
  ? await createWAFPool({ rules, mode, size: poolSize })
  : await createWAF({ rules, mode })

const app = Fastify({ logger: false, bodyLimit: 5 * 1024 * 1024 })

// Buffer multipart bodies so the Coraza preHandler hook sees the raw
// bytes via req.body. `@fastify/multipart` would consume the stream
// before preHandler and the WAF would see no body — by registering our
// own buffer parser instead we keep the request bytes inspectable, then
// parse with busboy from the buffer in the route handler.
app.addContentTypeParser(
  'multipart/form-data',
  { parseAs: 'buffer' },
  (_req, body, done) => done(null, body),
)

await app.register(formbody)
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
app.post('/form', async (req) => ({ received: req.body }))
app.post('/upload', async (req, reply) => {
  const ct = String(req.headers['content-type'] ?? '')
  if (!ct.startsWith('multipart/form-data') || !Buffer.isBuffer(req.body)) {
    reply.code(400)
    return { error: 'expected multipart/form-data' }
  }
  return await new Promise((resolve, reject) => {
    const fields: string[] = []
    const files: { name: string; bytes: number; field: string }[] = []
    const bb = Busboy({ headers: { 'content-type': ct } })
    bb.on('field', (name) => fields.push(name))
    bb.on('file', (field, stream, info) => {
      let bytes = 0
      stream.on('data', (chunk: Buffer) => {
        bytes += chunk.length
      })
      stream.on('end', () => {
        files.push({ name: info.filename, bytes, field })
      })
      stream.on('error', reject)
    })
    bb.on('error', reject)
    bb.on('close', () => resolve({ fields, files }))
    Readable.from([req.body as Buffer]).pipe(bb)
  })
})

await app.listen({ port, host: '0.0.0.0' })
process.stdout.write(`matrix-fastify5 listening on :${port}\n`)
process.on('SIGTERM', async () => {
  await app.close()
  process.exit(0)
})

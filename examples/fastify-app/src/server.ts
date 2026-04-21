import os from 'node:os'
import Fastify from 'fastify'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { coraza } from '@coraza/fastify'
import { ftwEcho, ftwModeEnabled, handlers } from '@coraza/example-shared'

const port = Number(process.env.PORT ?? 3002)
const ftw = ftwModeEnabled()
const mode = ftw ? 'block' : ((process.env.MODE ?? 'block') as 'detect' | 'block')
const wafDisabled = process.env.WAF === 'off'
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? os.availableParallelism())

const app = Fastify({ logger: false, bodyLimit: 10 * 1024 * 1024 })

app.addContentTypeParser(
  'application/octet-stream',
  { parseAs: 'buffer' },
  (_req, body, done) => done(null, body),
)

// Under FTW the test corpus sends many content-types. Parse everything
// as a raw buffer so Coraza evaluates exactly the payload on the wire.
if (ftw) {
  app.addContentTypeParser('*', { parseAs: 'buffer' }, (_req, body, done) =>
    done(null, body),
  )
}

if (!wafDisabled) {
  const rules = recommended(ftw ? { paranoia: 2 } : {})
  const waf = usePool
    ? await createWAFPool({ rules, mode, size: poolSize })
    : await createWAF({ rules, mode })
  await app.register(coraza, { waf, inspectResponse: ftw })
}

if (ftw) {
  // Fastify v5's find-my-way router accepts `/*` as the catch-all
  // pattern with no parameter name required.
  app.all('/*', async (req, reply) => {
    const headers: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === 'string') headers[k] = v
      else if (Array.isArray(v)) headers[k] = v.join(',')
    }
    const raw = req.body
    const body = Buffer.isBuffer(raw)
      ? raw.toString('utf8')
      : typeof raw === 'string'
        ? raw
        : JSON.stringify(raw ?? '')
    const r = ftwEcho({ method: req.method, url: req.url, headers, body })
    reply.status(r.status).type(r.contentType)
    return r.body
  })
} else {
  app.get('/', async () => handlers.root('fastify').body)
  app.get('/healthz', async (_req, reply) => {
    reply.type('text/plain')
    return handlers.healthz().body
  })
  app.get<{ Querystring: { q?: string } }>(
    '/search',
    async (req) => handlers.search(req.query.q).body,
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
  app.get<{ Params: { id: string } }>(
    '/api/users/:id',
    async (req) => handlers.user(req.params.id).body,
  )
}

process.stderr.write(`[${new Date().toISOString()}] fastify calling listen()\n`)
await app.listen({ port, host: '0.0.0.0' })
process.stderr.write(
  `[${new Date().toISOString()}] fastify listen resolved; address=${JSON.stringify(app.server.address())}\n`,
)

// Under FTW mode the CRS corpus sends CONNECT requests (SSL tunneling
// tests). Node's http.Server closes the socket when no `connect`
// listener is registered, which go-ftw surfaces as `unexpected EOF`
// and treats as a hard error — aborting the whole run. Respond 501 so
// go-ftw reads a proper HTTP status line and moves on. Fastify's WAF
// hook never sees CONNECT because it never reaches Fastify's request
// dispatch; phase-1 analysis doesn't apply to the CONNECT verb anyway.
if (ftw) {
  app.server.on('connect', (_req, socket) => {
    socket.write(
      'HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n',
    )
    socket.end()
  })
}
console.log(
  `fastify listening on :${port} (mode=${mode}, waf=${wafDisabled ? 'off' : 'on'}${ftw ? ', FTW=1 paranoia=2' : ''})`,
)

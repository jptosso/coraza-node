// plain-esm — `import { createWAF } from "@coraza/core"` with zero framework,
// zero bundler. Validates the ESM resolve path of @coraza/core end-to-end.

import http from 'node:http'
import querystring from 'node:querystring'
import { Readable } from 'node:stream'
import Busboy from 'busboy'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'

const port = Number(process.env.PORT ?? 3000)
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)
const mode = process.env.MODE ?? 'block'
// Same three-rule disable as examples/express-app — without these the
// inbound anomaly score crosses the PL1 threshold of 5 on every benign
// body-bearing POST and the matrix can't show the benign/malicious split.
const crsTuning = [
  'SecRuleRemoveById 920420',
  'SecRuleRemoveById 920350',
  'SecRuleRemoveById 922110',
].join('\n')
const rules = recommended({ extra: crsTuning })
const waf = usePool
  ? await createWAFPool({ rules, mode, size: poolSize })
  : await createWAF({ rules, mode })

function sendJson(res, status, body, contentType) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body)
  res.writeHead(status, { 'content-type': contentType || 'application/json' })
  res.end(payload)
}

async function readBody(req) {
  const chunks = []
  for await (const c of req) chunks.push(c)
  return Buffer.concat(chunks)
}

function parseMultipart(buf, contentType) {
  return new Promise((resolve, reject) => {
    const fields = []
    const files = []
    const bb = Busboy({ headers: { 'content-type': contentType } })
    bb.on('field', (name) => fields.push(name))
    bb.on('file', (field, stream, info) => {
      let bytes = 0
      stream.on('data', (chunk) => { bytes += chunk.length })
      stream.on('end', () => files.push({ name: info.filename, bytes, field }))
      stream.on('error', reject)
    })
    bb.on('error', reject)
    bb.on('close', () => resolve({ fields, files }))
    Readable.from([buf]).pipe(bb)
  })
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`)
  if (req.method === 'GET' && url.pathname === '/healthz') {
    return sendJson(res, 200, 'ok', 'text/plain')
  }

  const body =
    req.method === 'GET' || req.method === 'HEAD' ? Buffer.alloc(0) : await readBody(req)

  const tx = await waf.newTransaction()
  try {
    const headers = []
    for (const [k, v] of Object.entries(req.headers)) {
      if (v == null) continue
      if (Array.isArray(v)) for (const vv of v) headers.push([k, vv])
      else headers.push([k, String(v)])
    }
    const interrupted = await tx.processRequestBundle(
      {
        method: req.method || 'GET',
        url: url.pathname + url.search,
        protocol: 'HTTP/1.1',
        headers,
        remoteAddr: req.socket.remoteAddress || '',
      },
      body.length > 0 ? new Uint8Array(body) : undefined,
    )
    if (interrupted) {
      const interruption = await tx.interruption()
      const status = interruption?.status || 403
      return sendJson(res, status, `blocked by rule ${interruption?.ruleId ?? 0}`, 'text/plain')
    }

    if (req.method === 'GET' && url.pathname === '/') {
      return sendJson(res, 200, { ok: true })
    }
    if (req.method === 'GET' && url.pathname === '/search') {
      const q = url.searchParams.get('q') ?? ''
      return sendJson(res, 200, { q, len: q.length })
    }
    if (req.method === 'POST' && url.pathname === '/echo') {
      let parsed
      try { parsed = JSON.parse(body.toString('utf8') || '{}') } catch { parsed = {} }
      return sendJson(res, 200, parsed)
    }
    if (req.method === 'POST' && url.pathname === '/form') {
      const ct = String(req.headers['content-type'] || '')
      if (!ct.startsWith('application/x-www-form-urlencoded')) {
        return sendJson(res, 400, { error: 'expected application/x-www-form-urlencoded' })
      }
      const parsed = querystring.parse(body.toString('utf8'))
      return sendJson(res, 200, { received: parsed })
    }
    if (req.method === 'POST' && url.pathname === '/upload') {
      const ct = String(req.headers['content-type'] || '')
      if (!ct.startsWith('multipart/form-data')) {
        return sendJson(res, 400, { error: 'expected multipart/form-data' })
      }
      const parsed = await parseMultipart(body, ct)
      return sendJson(res, 200, parsed)
    }
    sendJson(res, 404, { error: 'not found' })
  } finally {
    await tx.processLogging()
    await tx.close()
  }
})

server.listen(port, '0.0.0.0', () => {
  process.stdout.write(`matrix-plain-esm listening on :${port}\n`)
})
process.on('SIGTERM', () => server.close(() => process.exit(0)))

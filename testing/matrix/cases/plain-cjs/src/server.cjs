// plain-cjs — `require("@coraza/core")` with zero framework. Validates
// that the package's `require` export actually resolves from a CJS
// consumer with no bundler shim.

const http = require('node:http')
const { createWAF, createWAFPool } = require('@coraza/core')
const { recommended } = require('@coraza/coreruleset')

const port = Number(process.env.PORT || 3000)
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE || 2)
const mode = process.env.MODE || 'block'

async function main() {
  const rules = recommended()
  const waf = usePool
    ? await createWAFPool({ rules, mode, size: poolSize })
    : await createWAF({ rules, mode })

  function sendJson(res, status, body, contentType) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body)
    res.writeHead(status, { 'content-type': contentType || 'application/json' })
    res.end(payload)
  }

  function readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = []
      req.on('data', (c) => chunks.push(c))
      req.on('end', () => resolve(Buffer.concat(chunks)))
      req.on('error', reject)
    })
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://' + (req.headers.host || 'localhost'))
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
          headers: headers,
          remoteAddr: req.socket.remoteAddress || '',
        },
        body.length > 0 ? new Uint8Array(body) : undefined,
      )
      if (interrupted) {
        const interruption = await tx.interruption()
        const status = (interruption && interruption.status) || 403
        return sendJson(
          res,
          status,
          'blocked by rule ' + (interruption ? interruption.ruleId : 0),
          'text/plain',
        )
      }

      if (req.method === 'GET' && url.pathname === '/') {
        return sendJson(res, 200, { ok: true })
      }
      if (req.method === 'GET' && url.pathname === '/search') {
        const q = url.searchParams.get('q') || ''
        return sendJson(res, 200, { q: q, len: q.length })
      }
      if (req.method === 'POST' && url.pathname === '/echo') {
        let parsed
        try { parsed = JSON.parse(body.toString('utf8') || '{}') } catch { parsed = {} }
        return sendJson(res, 200, parsed)
      }
      sendJson(res, 404, { error: 'not found' })
    } finally {
      await tx.processLogging()
      await tx.close()
    }
  })

  server.listen(port, '0.0.0.0', () => {
    process.stdout.write('matrix-plain-cjs listening on :' + port + '\n')
  })
  process.on('SIGTERM', () => server.close(() => process.exit(0)))
}

main().catch((err) => {
  process.stderr.write('matrix-plain-cjs: ' + (err && err.stack ? err.stack : err) + '\n')
  process.exit(1)
})

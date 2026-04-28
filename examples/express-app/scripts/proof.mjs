// Local proof harness for the express example. Spawns the dev server,
// drives every endpoint shape (JSON, urlencoded, multipart, file download,
// WebSocket) with a benign + a malicious payload, prints the status code
// per scenario, then tears down. Lives under examples/ — keep simple.
//
// Note: paths are passed verbatim (`http.request({ path: ... })`) instead
// of URL strings so the WAF sees `..` traversal sequences exactly as the
// attacker would send them — `new URL(...)` would normalize them out
// before they reach the wire.

import { spawn } from 'node:child_process'
import { setTimeout as wait } from 'node:timers/promises'
import http from 'node:http'

const PORT = Number(process.env.PORT ?? 3041)
const REPO = process.env.REPO ?? process.cwd()

// Default headers mimic a real browser. Without these the OWASP CRS
// scoring rules (920280 missing host, 920320 missing UA, 920300 missing
// accept) stack into the 949110 anomaly threshold even on benign traffic.
const baseHeaders = {
  'user-agent': 'coraza-proof/1.0',
  accept: '*/*',
}

function get(rawPath, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: PORT,
        method: 'GET',
        path: rawPath,
        headers: baseHeaders,
        ...opts,
      },
      (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks) }),
        )
      },
    )
    req.on('error', reject)
    req.end()
  })
}

function post(rawPath, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const buf =
      body == null
        ? Buffer.alloc(0)
        : Buffer.isBuffer(body)
          ? body
          : Buffer.from(String(body))
    const finalHeaders = {
      ...baseHeaders,
      'content-length': String(buf.length),
      ...headers,
    }
    const req = http.request(
      {
        host: '127.0.0.1',
        port: PORT,
        method: 'POST',
        path: rawPath,
        headers: finalHeaders,
      },
      (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks) }),
        )
      },
    )
    req.on('error', reject)
    if (buf.length) req.write(buf)
    req.end()
  })
}

function postMultipart(rawPath, files) {
  const boundary = '----coraza' + Math.random().toString(16).slice(2)
  const parts = []
  for (const f of files) {
    parts.push(Buffer.from(`--${boundary}\r\n`))
    parts.push(
      Buffer.from(
        `Content-Disposition: form-data; name="${f.field}"; filename="${f.filename}"\r\nContent-Type: text/plain\r\n\r\n`,
      ),
    )
    parts.push(f.content)
    parts.push(Buffer.from('\r\n'))
  }
  parts.push(Buffer.from(`--${boundary}--\r\n`))
  const body = Buffer.concat(parts)
  return post(rawPath, body, {
    'content-type': `multipart/form-data; boundary=${boundary}`,
  })
}

async function waitForServer(timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const r = await get('/healthz')
      if (r.status === 200) return
    } catch {
      /* not ready */
    }
    await wait(200)
  }
  throw new Error('server did not come up')
}

async function main() {
  const child = spawn('pnpm', ['-F', '@coraza/example-express', 'dev'], {
    cwd: REPO,
    env: { ...process.env, PORT: String(PORT), MODE: process.env.MODE ?? 'block' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let log = ''
  child.stdout.on('data', (d) => {
    log += d.toString()
    process.stderr.write('[srv] ' + d.toString())
  })
  child.stderr.on('data', (d) => {
    log += d.toString()
    process.stderr.write('[srv-err] ' + d.toString())
  })

  try {
    await waitForServer()
  } catch (err) {
    console.error('server boot failed; tail of log:')
    console.error(log.slice(-3000))
    child.kill('SIGTERM')
    process.exit(1)
  }

  const out = []
  const log_line = (label, code) => {
    console.log(`${label} ${code}`)
    out.push([label, code])
  }

  // JSON
  let r = await post('/echo', JSON.stringify({ q: 'hello' }), {
    'content-type': 'application/json',
  })
  log_line('echo-benign', r.status)
  r = await post('/echo', JSON.stringify({ q: "' OR 1=1--" }), {
    'content-type': 'application/json',
  })
  log_line('echo-sqli', r.status)

  // urlencoded
  r = await post('/form', 'q=hello', {
    'content-type': 'application/x-www-form-urlencoded',
  })
  log_line('form-benign', r.status)
  r = await post('/form', 'q=%27+OR+1%3D1--', {
    'content-type': 'application/x-www-form-urlencoded',
  })
  log_line('form-sqli', r.status)

  // multipart
  r = await postMultipart('/upload', [
    { field: 'file', filename: 'benign.txt', content: Buffer.from('hello\n') },
  ])
  log_line('upload-benign', r.status)
  // CRS at PL1 doesn't pattern-match multipart filenames against XSS rules
  // (it inspects ARGS = field values, plus FILES_NAMES against the
  // restricted-extension list). To demonstrate the WAF is actually
  // looking at multipart bodies we put a SQLi pattern in a field value —
  // that path goes through ARGS and trips the same SQLi rules as the
  // urlencoded /form case.
  r = await postMultipart('/upload', [
    { field: 'q', filename: '', content: Buffer.from("' OR 1=1--") },
    { field: 'file', filename: 'benign.txt', content: Buffer.from('hello\n') },
  ])
  log_line('upload-sqli', r.status)
  // Also probe the original task example so the report records it.
  r = await postMultipart('/upload', [
    {
      field: 'file',
      filename: '<script>alert(1)</script>.txt',
      content: Buffer.from('x\n'),
    },
  ])
  log_line('upload-xss-filename', r.status)

  // download
  r = await get('/download/test.txt')
  log_line('download-benign', r.status)
  r = await get('/download/../../etc/passwd')
  log_line('download-traversal', r.status)

  // websocket
  const { default: WebSocket } = await import('ws')
  await new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/ws/echo`)
    let echoed = false
    ws.on('open', () => ws.send('hi'))
    ws.on('message', (m) => {
      if (m.toString().startsWith('[srv] ')) echoed = true
      ws.close()
    })
    ws.on('close', () => {
      log_line('ws-benign', echoed ? 'echoed' : 'no-echo')
      resolve()
    })
    ws.on('error', () => {
      log_line('ws-benign', 'error')
      resolve()
    })
  })
  await new Promise((resolve) => {
    let logged = false
    const finish = (val) => {
      if (logged) return
      logged = true
      log_line('ws-sqli', val)
      resolve()
    }
    const ws = new WebSocket(
      `ws://127.0.0.1:${PORT}/ws/echo?q=${encodeURIComponent("' OR 1=1--")}`,
    )
    let opened = false
    let httpStatus = null
    ws.on('open', () => {
      opened = true
      ws.close()
    })
    ws.on('unexpected-response', (_req, res) => {
      httpStatus = res.statusCode
      finish(httpStatus)
    })
    ws.on('error', () => {
      /* expected — connection refused after 403; finish via close */
    })
    ws.on('close', () => {
      finish(opened ? 'OPENED-UNEXPECTED' : (httpStatus ?? 'closed'))
    })
    setTimeout(() => finish('timeout'), 5000)
  })

  child.kill('SIGTERM')
  await wait(300)
  console.log('---SUMMARY---')
  for (const [k, v] of out) console.log(k, v)
}

main().catch((err) => {
  console.error('harness error:', err)
  process.exit(1)
})

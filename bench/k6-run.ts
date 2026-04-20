// k6-driven E2E benchmark runner. Boots each example app with WAF=off
// then WAF=on, runs the mixed-traffic k6 script against it, and prints a
// per-adapter comparison. Complements bench/run.ts (autocannon) with a
// heavier, more realistic traffic mix.
//
// Prerequisites:
//   - k6 on PATH (https://k6.io/docs/get-started/installation/)
//   - pnpm build (example apps must be runnable)
//   - packages/core/src/wasm/coraza.wasm (required for WAF=on runs)
//
// Usage:
//   pnpm --filter @coraza/bench k6
//   pnpm --filter @coraza/bench k6 --adapters=express --duration=15s

import { spawn, type ChildProcess } from 'node:child_process'
import { setTimeout as delay } from 'node:timers/promises'
import { which } from './util.js'

interface AdapterDef {
  name: string
  port: number
  cwd: string
  cmd: string
  args: string[]
}

const ROOT = new URL('..', import.meta.url).pathname

const ADAPTERS: Record<string, AdapterDef> = {
  express: {
    name: 'express',
    port: 3001,
    cwd: `${ROOT}examples/express-app`,
    cmd: 'node',
    args: ['--import', 'tsx', 'src/server.ts'],
  },
  fastify: {
    name: 'fastify',
    port: 3002,
    cwd: `${ROOT}examples/fastify-app`,
    cmd: 'node',
    args: ['--import', 'tsx', 'src/server.ts'],
  },
  nestjs: {
    name: 'nestjs',
    port: 3004,
    cwd: `${ROOT}examples/nestjs-app`,
    cmd: 'node',
    args: ['--import', 'tsx', 'src/main.ts'],
  },
  next: {
    name: 'next',
    port: 3003,
    cwd: `${ROOT}examples/next-app`,
    cmd: 'pnpm',
    args: ['dev'],
  },
}

interface Args {
  adapters: string[]
  duration: string
  vus: number
  warmup: number
}

function parseArgs(): Args {
  const a: Args = {
    adapters: ['express', 'fastify', 'nestjs'],
    duration: '20s',
    vus: 50,
    warmup: 3,
  }
  for (const raw of process.argv.slice(2)) {
    const [k, v] = raw.replace(/^--/, '').split('=', 2) as [string, string | undefined]
    if (k === 'adapters' && v) a.adapters = v.split(',')
    else if (k === 'duration' && v) a.duration = v
    else if (k === 'vus' && v) a.vus = Number(v)
    else if (k === 'warmup' && v) a.warmup = Number(v)
  }
  return a
}

async function waitForHealth(port: number, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`)
      if (res.status < 500) return
    } catch {
      /* keep polling */
    }
    await delay(200)
  }
  throw new Error(`server on :${port} did not come up in ${timeoutMs}ms`)
}

async function boot(adapter: AdapterDef, wafOn: boolean): Promise<ChildProcess> {
  const env = {
    ...process.env,
    PORT: String(adapter.port),
    MODE: 'block',
    WAF: wafOn ? 'on' : 'off',
  }
  const child = spawn(adapter.cmd, adapter.args, {
    cwd: adapter.cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stderr!.on('data', (b) => process.stderr.write(`[${adapter.name}] ${b}`))
  await waitForHealth(adapter.port)
  return child
}

async function shutdown(child: ChildProcess): Promise<void> {
  if (child.killed) return
  child.kill('SIGTERM')
  await new Promise<void>((resolve) => {
    const t = setTimeout(() => {
      child.kill('SIGKILL')
      resolve()
    }, 5_000)
    child.once('exit', () => {
      clearTimeout(t)
      resolve()
    })
  })
}

interface K6Summary {
  http_reqs: number
  http_req_rate: number
  http_req_duration: { avg: number; p90: number; p95: number; p99: number }
  blocked: number
  missed: number
  checks_rate: number
}

async function runK6(adapter: AdapterDef, args: Args): Promise<K6Summary> {
  // Use k6's JSON summary export to get machine-readable numbers.
  const summaryFile = `/tmp/k6-${adapter.name}-${Date.now()}.json`
  const env = {
    ...process.env,
    BASE_URL: `http://127.0.0.1:${adapter.port}`,
    VUS: String(args.vus),
    DURATION: args.duration,
  }
  const child = spawn(
    'k6',
    [
      'run',
      '--summary-export',
      summaryFile,
      `${ROOT}bench/k6/mixed.js`,
    ],
    { env, stdio: ['ignore', 'inherit', 'inherit'] },
  )
  await new Promise<void>((resolve, reject) => {
    child.once('exit', (code) =>
      code === 0 || code === 99 /* threshold failure, but data is still there */
        ? resolve()
        : reject(new Error(`k6 exited ${code}`)),
    )
    child.once('error', reject)
  })

  const fs = await import('node:fs/promises')
  type Metric = Record<string, number | undefined>
  const raw = JSON.parse(await fs.readFile(summaryFile, 'utf8')) as {
    metrics: Record<string, Metric>
  }
  const dur = raw.metrics.http_req_duration ?? {}
  const reqs = raw.metrics.http_reqs ?? {}
  return {
    http_reqs: Number(reqs.count ?? 0),
    http_req_rate: Number(reqs.rate ?? 0),
    http_req_duration: {
      avg: Number(dur.avg ?? 0),
      p90: Number(dur['p(90)'] ?? 0),
      p95: Number(dur['p(95)'] ?? 0),
      p99: Number(dur['p(99)'] ?? 0),
    },
    blocked: Number(raw.metrics.blocked_attacks?.count ?? 0),
    missed: Number(raw.metrics.missed_attacks?.count ?? 0),
    checks_rate: Number(raw.metrics.checks?.rate ?? 1),
  }
}

function fmt(n: number, decimals = 1): string {
  return n.toFixed(decimals)
}

function renderTable(name: string, off: K6Summary, on: K6Summary): string {
  const rows = [
    ['RPS', fmt(off.http_req_rate), fmt(on.http_req_rate), pct(on.http_req_rate, off.http_req_rate)],
    ['avg ms', fmt(off.http_req_duration.avg), fmt(on.http_req_duration.avg), pct(on.http_req_duration.avg, off.http_req_duration.avg)],
    ['p95 ms', fmt(off.http_req_duration.p95), fmt(on.http_req_duration.p95), pct(on.http_req_duration.p95, off.http_req_duration.p95)],
    ['p99 ms', fmt(off.http_req_duration.p99), fmt(on.http_req_duration.p99), pct(on.http_req_duration.p99, off.http_req_duration.p99)],
    ['attacks blocked', '—', String(on.blocked), ''],
    ['attacks missed', '—', String(on.missed), ''],
  ]
  const widths = [15, 10, 10, 10]
  const fmtRow = (r: string[]) => r.map((c, i) => c.padEnd(widths[i]!)).join('  ')
  return [
    `\n== ${name} — k6 mixed traffic (WAF off vs on) ==`,
    fmtRow(['metric', 'off', 'on', 'Δ']),
    widths.map((w) => '-'.repeat(w)).join('  '),
    ...rows.map(fmtRow),
  ].join('\n')
}

function pct(on: number, off: number): string {
  if (off === 0) return 'n/a'
  const p = ((on - off) / off) * 100
  const sign = p >= 0 ? '+' : ''
  return `${sign}${p.toFixed(1)}%`
}

async function main(): Promise<void> {
  if (!(await which('k6'))) {
    console.error('k6 not found on PATH. Install from https://k6.io/docs/get-started/installation/')
    process.exit(2)
  }
  const args = parseArgs()
  const tables: string[] = []

  for (const name of args.adapters) {
    const adapter = ADAPTERS[name]
    if (!adapter) {
      console.error(`unknown adapter: ${name}`)
      continue
    }

    process.stderr.write(`\n-- ${adapter.name}: WAF=off\n`)
    const offProc = await boot(adapter, false)
    await delay(args.warmup * 1000)
    const off = await runK6(adapter, args)
    await shutdown(offProc)

    process.stderr.write(`-- ${adapter.name}: WAF=on\n`)
    const onProc = await boot(adapter, true)
    await delay(args.warmup * 1000)
    const on = await runK6(adapter, args)
    await shutdown(onProc)

    tables.push(renderTable(adapter.name, off, on))
  }
  console.log(tables.join('\n'))
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})

// End-to-end benchmark runner for coraza-node adapters.
//
// For each selected adapter:
//   1. Boot the example app with WAF=on
//   2. Run autocannon against every shared-contract scenario
//   3. Boot the example app with WAF=off
//   4. Re-run the same scenarios
//   5. Print a table comparing throughput and latency
//
// Usage:
//   pnpm --filter @coraza/bench bench --adapters=express,fastify
//   pnpm --filter @coraza/bench bench --duration=15 --connections=50

import { spawn, type ChildProcess } from 'node:child_process'
import { setTimeout as delay } from 'node:timers/promises'
import autocannon from 'autocannon'
import { benchScenarios } from '@coraza/example-shared'

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

interface CliArgs {
  adapters: string[]
  duration: number
  connections: number
  warmup: number
}

function parseArgs(): CliArgs {
  const argv = process.argv.slice(2)
  const opts: CliArgs = {
    adapters: ['express', 'fastify', 'nestjs'],
    duration: 10,
    connections: 30,
    warmup: 2,
  }
  for (const arg of argv) {
    const [k, v] = arg.replace(/^--/, '').split('=', 2) as [string, string | undefined]
    if (k === 'adapters' && v) opts.adapters = v.split(',')
    else if (k === 'duration' && v) opts.duration = Number(v)
    else if (k === 'connections' && v) opts.connections = Number(v)
    else if (k === 'warmup' && v) opts.warmup = Number(v)
  }
  return opts
}

async function waitForPort(host: string, port: number, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://${host}:${port}/healthz`)
      if (res.status < 500) return
    } catch {
      // not ready yet
    }
    await delay(200)
  }
  throw new Error(`server on :${port} did not come up in ${timeoutMs}ms`)
}

async function boot(adapter: AdapterDef, wafOn: boolean): Promise<ChildProcess> {
  const env = {
    ...process.env,
    PORT: String(adapter.port),
    MODE: 'detect', // bench with detect so rules run but no block-cost delta
    WAF: wafOn ? 'on' : 'off',
  }
  const child = spawn(adapter.cmd, adapter.args, {
    cwd: adapter.cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stderr!.on('data', (chunk) => process.stderr.write(`[${adapter.name}] ${chunk}`))
  await waitForPort('127.0.0.1', adapter.port)
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

interface Result {
  scenario: string
  rps: number
  p50: number
  p99: number
  non2xx: number
}

async function runScenarios(
  adapter: AdapterDef,
  cli: CliArgs,
  tag: 'on' | 'off',
): Promise<Result[]> {
  const results: Result[] = []
  for (const s of benchScenarios) {
    const isPost = s.method === 'POST'
    const body = 'body' in s && s.body !== undefined
      ? typeof s.body === 'string'
        ? s.body
        : JSON.stringify(s.body)
      : undefined
    const contentType =
      'contentType' in s && typeof s.contentType === 'string'
        ? s.contentType
        : isPost
          ? 'application/json'
          : undefined

    const res = await autocannon({
      url: `http://127.0.0.1:${adapter.port}${s.path}`,
      method: s.method,
      connections: cli.connections,
      duration: cli.duration,
      body,
      headers: contentType ? { 'content-type': contentType } : {},
    })
    results.push({
      scenario: s.label,
      rps: Math.round(res.requests.average),
      p50: res.latency.p50,
      p99: res.latency.p99,
      non2xx: res.non2xx,
    })
    process.stderr.write(
      `  ${adapter.name}/${tag}/${s.label}: rps=${results.at(-1)!.rps} p50=${res.latency.p50}ms\n`,
    )
  }
  return results
}

function table(
  adapter: string,
  onRows: Result[],
  offRows: Result[],
): string {
  const headers = ['scenario', 'rps (off)', 'rps (on)', 'Δ rps %', 'p99 (off)', 'p99 (on)', 'Δ p99 ms']
  const rows = onRows.map((onR, i) => {
    const offR = offRows[i]!
    const dRps = offR.rps === 0 ? 'n/a' : (((onR.rps - offR.rps) / offR.rps) * 100).toFixed(1) + '%'
    const dP99 = (onR.p99 - offR.p99).toFixed(1)
    return [onR.scenario, offR.rps, onR.rps, dRps, offR.p99, onR.p99, dP99]
  })
  const widths = headers.map((h, ci) =>
    Math.max(h.length, ...rows.map((r) => String(r[ci]).length)),
  )
  const fmt = (cells: (string | number)[]): string =>
    cells.map((c, i) => String(c).padEnd(widths[i]!)).join('  ')
  return [
    `\n== ${adapter} — Coraza WAF impact (WAF=on vs WAF=off) ==`,
    fmt(headers),
    widths.map((w) => '-'.repeat(w)).join('  '),
    ...rows.map(fmt),
  ].join('\n')
}

async function main(): Promise<void> {
  const cli = parseArgs()
  const all: string[] = []

  for (const name of cli.adapters) {
    const adapter = ADAPTERS[name]
    if (!adapter) {
      console.error(`unknown adapter: ${name}`)
      continue
    }

    process.stderr.write(`\n-- ${adapter.name}: booting WAF=off\n`)
    const offProc = await boot(adapter, false)
    await delay(cli.warmup * 1000)
    const offRows = await runScenarios(adapter, cli, 'off')
    await shutdown(offProc)

    process.stderr.write(`-- ${adapter.name}: booting WAF=on\n`)
    const onProc = await boot(adapter, true)
    await delay(cli.warmup * 1000)
    const onRows = await runScenarios(adapter, cli, 'on')
    await shutdown(onProc)

    all.push(table(adapter.name, onRows, offRows))
  }

  console.log(all.join('\n'))
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})

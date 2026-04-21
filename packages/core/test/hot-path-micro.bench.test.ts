// Ad-hoc micro-benchmark for Proposal #4 (bundle encode) + a probe of the
// readString candidate from Proposal #8. Baseline helpers are inlined from
// develop-HEAD; branch helpers are imported from ../src/transaction.js.
//
// Run via: npx vitest run test/hot-path-micro.bench.test.ts
//
// The readString probe confirms TextDecoder.decode() is faster than
// Buffer.from().toString('utf8') for every realistic short read on Node 22+,
// which is why Proposal #8 was dropped rather than landed.

import { describe, it } from 'vitest'
import { performance } from 'node:perf_hooks'
import {
  encodeRequestBundle as branchEncodeRequestBundle,
} from '../src/transaction.js'
import { Abi } from '../src/abi.js'
import { createMock } from './mockAbi.js'

// --- Baseline (verbatim copy of develop-HEAD helpers) --- //

const baselineEncoder = new TextEncoder()

function b_truncateUtf8(b: Uint8Array, maxBytes: number): Uint8Array {
  if (b.length <= maxBytes) return b
  let end = maxBytes
  while (end > 0 && (b[end]! & 0xc0) === 0x80) end--
  return b.subarray(0, end)
}

function b_encodeHeaders(headers: Iterable<readonly [string, string]>): Uint8Array {
  const entries: { n: Uint8Array; v: Uint8Array }[] = []
  let total = 4
  for (const [name, value] of headers) {
    const n = baselineEncoder.encode(name)
    const v = baselineEncoder.encode(value)
    entries.push({ n, v })
    total += 4 + n.length + 4 + v.length
  }
  const out = new Uint8Array(total)
  const view = new DataView(out.buffer)
  view.setUint32(0, entries.length, true)
  let off = 4
  for (const { n, v } of entries) {
    view.setUint32(off, n.length, true); off += 4
    out.set(n, off); off += n.length
    view.setUint32(off, v.length, true); off += 4
    out.set(v, off); off += v.length
  }
  return out
}

type Req = {
  method: string
  url: string
  protocol?: string
  remoteAddr?: string
  remotePort?: number
  serverPort?: number
  headers: [string, string][]
}

function b_encodeRequestBundle(req: Req, body?: string | Uint8Array): Uint8Array {
  const method = b_truncateUtf8(baselineEncoder.encode(req.method), 255)
  const proto = b_truncateUtf8(baselineEncoder.encode(req.protocol ?? 'HTTP/1.1'), 255)
  const addr = b_truncateUtf8(baselineEncoder.encode(req.remoteAddr ?? ''), 65535)
  const url = baselineEncoder.encode(req.url)
  const cport = (req.remotePort ?? 0) & 0xffff
  const sport = (req.serverPort ?? 0) & 0xffff
  const hdrPkt = b_encodeHeaders(req.headers)
  const bodyBytes = typeof body === 'string' ? baselineEncoder.encode(body) : (body ?? new Uint8Array(0))
  const total =
    2 + addr.length + 2 + 2 +
    1 + method.length + 1 + proto.length +
    4 + url.length + 4 + hdrPkt.length + 4 + bodyBytes.length
  const out = new Uint8Array(total)
  const view = new DataView(out.buffer)
  let o = 0
  view.setUint16(o, addr.length, true); o += 2
  out.set(addr, o); o += addr.length
  view.setUint16(o, cport, true); o += 2
  view.setUint16(o, sport, true); o += 2
  out[o++] = method.length
  out.set(method, o); o += method.length
  out[o++] = proto.length
  out.set(proto, o); o += proto.length
  view.setUint32(o, url.length, true); o += 4
  out.set(url, o); o += url.length
  view.setUint32(o, hdrPkt.length, true); o += 4
  out.set(hdrPkt, o); o += hdrPkt.length
  view.setUint32(o, bodyBytes.length, true); o += 4
  out.set(bodyBytes, o)
  return out
}

// --- Proposal #8 baseline (TextDecoder always) --- //

const decoder = new TextDecoder('utf-8', { fatal: false })

function b_readString(mem: Uint8Array, ptr: number, len: number): string {
  if (len === 0) return ''
  return decoder.decode(mem.subarray(ptr, ptr + len))
}

// --- Driver --- //

function run<T>(fn: (i: number) => T, iters: number): number {
  for (let i = 0; i < Math.min(iters, 1000); i++) fn(i)
  const t0 = performance.now()
  for (let i = 0; i < iters; i++) fn(i)
  const elapsed = performance.now() - t0
  return iters / (elapsed / 1000)
}

function median(ns: number[]): number {
  return ns.slice().sort((a, b) => a - b)[Math.floor(ns.length / 2)]!
}

function pct(branch: number, base: number): string {
  const p = ((branch - base) / base) * 100
  return (p >= 0 ? '+' : '') + p.toFixed(2) + '%'
}

// Header-heavy sample that mirrors a realistic per-route request.
const sampleReq: Req = {
  method: 'POST',
  url: '/api/users?filter=active&sort=-created&limit=50',
  protocol: 'HTTP/1.1',
  remoteAddr: '203.0.113.45',
  remotePort: 58230,
  serverPort: 8080,
  headers: [
    ['host', 'api.example.com'],
    ['user-agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'],
    ['accept', 'application/json, text/plain, */*'],
    ['accept-encoding', 'gzip, deflate, br'],
    ['accept-language', 'en-US,en;q=0.9'],
    ['authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload-redacted.sig'],
    ['content-type', 'application/json'],
    ['content-length', '123'],
    ['cookie', 'sid=abc123; tracker=xyz; prefs=dark-mode'],
    ['x-request-id', '7c9b0f83-1f47-4b7d-9d4e-0000aabbccdd'],
    ['x-forwarded-for', '203.0.113.45, 10.0.0.1'],
    ['x-forwarded-proto', 'https'],
    ['referer', 'https://api.example.com/dashboard'],
    ['origin', 'https://api.example.com'],
  ],
}
const sampleBody = JSON.stringify({ name: 'alice', tags: ['a', 'b', 'c'], active: true })

// Inputs for readString micro-bench: small JSON blobs like interruption /
// matchedRules, plus a >4 KiB blob for the large-read branch.
const mem = new Uint8Array(65536)
const interruptionJson = new TextEncoder().encode(
  JSON.stringify({ ruleId: 942100, action: 'deny', status: 403, data: 'SQLi detected in query parameter' }),
)
const matchedRulesJson = new TextEncoder().encode(
  JSON.stringify(
    Array.from({ length: 8 }, (_, i) => ({
      id: 900000 + i,
      severity: 3,
      message: `Rule ${i} fired on input X — see docs for context`,
    })),
  ),
)
const largeBlob = new TextEncoder().encode('a'.repeat(8192))
mem.set(interruptionJson, 100)
mem.set(matchedRulesJson, 2000)
mem.set(largeBlob, 10000)

// Use the real Abi to make the short/long readString comparable.
const { exports } = createMock()
const abi = new Abi(exports)
abi.writeAt(100, interruptionJson)
abi.writeAt(2000, matchedRulesJson)
abi.writeAt(10000, largeBlob)

const ITERS = 300_000

describe('[bench] hot-path', () => {
  it('reports ops/sec for encodeRequestBundle (Proposal #4) and readString (Proposal #8)', () => {
    const N = 3
    const results: { name: string; base: number; branch: number }[] = []

    // #4 — bundle encode (header-heavy request)
    {
      const baseR: number[] = []
      const brR: number[] = []
      for (let k = 0; k < N; k++) {
        baseR.push(run((i) => b_encodeRequestBundle({ ...sampleReq, url: sampleReq.url + '&i=' + i }, sampleBody), ITERS))
        brR.push(run((i) => branchEncodeRequestBundle({ ...sampleReq, url: sampleReq.url + '&i=' + i }, sampleBody), ITERS))
      }
      results.push({ name: 'encodeRequestBundle (header-heavy)', base: median(baseR), branch: median(brR) })
    }

    // #8 — small reads (alternating interruption + matchedRules, ~180 & ~650 B)
    {
      const baseR: number[] = []
      const brR: number[] = []
      for (let k = 0; k < N; k++) {
        baseR.push(run((i) => {
          const off = (i & 1) ? 100 : 2000
          const len = (i & 1) ? interruptionJson.length : matchedRulesJson.length
          return b_readString(abi.bytes(), off, len)
        }, ITERS))
        brR.push(run((i) => {
          const off = (i & 1) ? 100 : 2000
          const len = (i & 1) ? interruptionJson.length : matchedRulesJson.length
          return abi.readString(off, len)
        }, ITERS))
      }
      results.push({ name: 'readString small (interruption+matchedRules)', base: median(baseR), branch: median(brR) })
    }

    // Raw Buffer vs TextDecoder probe across sizes — feeds threshold tuning.
    const probe = (len: number) => {
      const data = new TextEncoder().encode('x'.repeat(len))
      const m = abi.bytes()
      abi.writeAt(20000, data)
      const N2 = 3
      const baseR: number[] = []
      const bufR: number[] = []
      for (let k = 0; k < N2; k++) {
        baseR.push(run(() => decoder.decode(m.subarray(20000, 20000 + len)), ITERS))
        bufR.push(run(() => Buffer.from(m.buffer, m.byteOffset + 20000, len).toString('utf8'), ITERS))
      }
      results.push({ name: `probe len=${len} (TextDecoder vs Buffer)`, base: median(baseR), branch: median(bufR) })
    }
    probe(16)
    probe(32)
    probe(64)
    probe(128)
    probe(256)
    probe(512)
    probe(1024)
    probe(4096)
    probe(16384)

    // #8 control — large read should stay on TextDecoder path via readString()
    {
      const baseR: number[] = []
      const brR: number[] = []
      for (let k = 0; k < N; k++) {
        baseR.push(run(() => b_readString(abi.bytes(), 10000, largeBlob.length), ITERS))
        brR.push(run(() => abi.readString(10000, largeBlob.length), ITERS))
      }
      results.push({ name: 'readString large (>=4 KiB, control)', base: median(baseR), branch: median(brR) })
    }

    const w = [38, 18, 18, 10]
    const fmt = (cols: string[]) => cols.map((c, i) => c.padEnd(w[i]!)).join('  ')
    const out: string[] = []
    out.push('')
    out.push('== coraza-node hot-path micro-bench (median of 3) ==')
    out.push(fmt(['case', 'baseline ops/s', 'branch ops/s', 'Δ%']))
    out.push(w.map((x) => '-'.repeat(x)).join('  '))
    for (const r of results) {
      out.push(fmt([
        r.name,
        Math.round(r.base).toLocaleString(),
        Math.round(r.branch).toLocaleString(),
        pct(r.branch, r.base),
      ]))
    }
    out.push('')
    // eslint-disable-next-line no-console
    console.log(out.join('\n'))
  }, 60_000)
})

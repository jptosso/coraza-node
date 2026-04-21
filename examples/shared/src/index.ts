// Shared HTTP contract that every example app (express, fastify, next, nestjs)
// implements identically. The goal: apples-to-apples benchmarks and a single
// traffic generator that drives all four servers the same way.
//
// Route matrix:
//
//   GET  /                → JSON { ok: true, name: "<adapter>" }
//   GET  /healthz         → text "ok" (no body)
//   GET  /search?q=...    → JSON { q, len }
//   POST /echo            → JSON body back
//   POST /upload          → returns size of body in bytes
//   GET  /img/logo.png    → fake PNG bytes (drives the skip path)
//   GET  /api/users/:id   → JSON { id }
//
// When the app is started with `FTW=1`, a single additional route
// is mounted that every adapter implements identically — the go-ftw
// test runner fires every CRS test case at it:
//
//   ALL  /*               → 200 with an echo of method + URL + headers +
//                           body back. Identical shape across adapters so
//                           a single overrides YAML applies to all legs.
//
// The FTW endpoint deliberately echoes the request body into the
// response so RESPONSE-* rules fire. Next's middleware doesn't see
// response bodies — its outbound-only leg gets a lower pass-rate
// threshold in the workflow (documented in ftw-overrides.yaml).
//
// Each adapter-specific server file imports HANDLERS, SAMPLE_PNG, and
// FTW_* helpers from this module. Keep framework-specific code out of
// here.

export const SAMPLE_PNG = Buffer.from([
  // 1×1 transparent PNG, enough to satisfy clients expecting image bytes.
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
  0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
  0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
  0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
  0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
])

export interface HandlerResult {
  status?: number
  body: unknown
  contentType?: string
}

export const handlers = {
  root(adapter: string): HandlerResult {
    return { body: { ok: true, name: adapter } }
  },
  healthz(): HandlerResult {
    return { body: 'ok', contentType: 'text/plain' }
  },
  search(q: string | undefined): HandlerResult {
    const value = q ?? ''
    return { body: { q: value, len: value.length } }
  },
  echo(input: unknown): HandlerResult {
    return { body: input ?? {} }
  },
  upload(bytes: number): HandlerResult {
    return { body: { bytes } }
  },
  image(): HandlerResult {
    return { status: 200, body: SAMPLE_PNG, contentType: 'image/png' }
  },
  user(id: string): HandlerResult {
    return { body: { id } }
  },
}

/**
 * FTW mode is the single toggle every adapter inspects. `FTW=1` in the
 * environment switches the app into "mount the echo-all route, run CRS
 * at paranoia 2 in block mode, otherwise behave normally". The variable
 * name is stable so the GHA matrix can flip it the same way for every
 * adapter leg.
 */
export function ftwModeEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.FTW === '1'
}

export interface FtwEchoInput {
  method: string
  url: string
  headers: Record<string, string>
  body: string
}

/**
 * Build the response body the FTW echo-all route returns. Keeping this
 * in shared-land means every adapter emits byte-identical JSON, so one
 * overrides YAML is enough for the whole matrix.
 */
export function ftwEcho(input: FtwEchoInput): {
  status: number
  body: FtwEchoInput
  contentType: string
} {
  return {
    status: 200,
    body: {
      method: input.method,
      url: input.url,
      headers: input.headers,
      body: input.body,
    },
    contentType: 'application/json',
  }
}

/** Canonical traffic mix used by benchmarks. */
export const benchScenarios = [
  { label: 'root', method: 'GET', path: '/' },
  { label: 'healthz', method: 'GET', path: '/healthz' },
  { label: 'search-clean', method: 'GET', path: '/search?q=hello' },
  { label: 'search-sqli', method: 'GET', path: "/search?q='+OR+1=1--" },
  { label: 'echo-json', method: 'POST', path: '/echo', body: { msg: 'hi' } },
  {
    label: 'echo-xss',
    method: 'POST',
    path: '/echo',
    body: { msg: '<script>alert(1)</script>' },
  },
  {
    label: 'upload-1kb',
    method: 'POST',
    path: '/upload',
    body: 'x'.repeat(1024),
    contentType: 'application/octet-stream',
  },
  { label: 'static-png', method: 'GET', path: '/img/logo.png' },
  { label: 'user-by-id', method: 'GET', path: '/api/users/42' },
] as const

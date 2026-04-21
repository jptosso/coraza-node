import { NextResponse } from 'next/server'
import { ftwEcho, ftwModeEnabled } from '@coraza/example-shared'

// Next App Router treats `[...slug]` as a lowest-priority catch-all: any
// request that didn't match a more-specific route falls through here.
// When FTW=1 the go-ftw corpus targets URLs the demo routes don't
// define, so this handler echoes the request back, which is what the
// FTW contract expects. When FTW=0 it 404s, matching the prior demo
// behaviour for unknown paths.

async function handle(req: Request): Promise<Response> {
  if (!ftwModeEnabled()) {
    return new Response('not found', { status: 404 })
  }
  const headers: Record<string, string> = {}
  req.headers.forEach((v, k) => {
    headers[k] = v
  })
  const body = await req.text().catch(() => '')
  const r = ftwEcho({ method: req.method, url: req.url, headers, body })
  return NextResponse.json(r.body, { status: r.status })
}

export const GET = handle
export const POST = handle
export const PUT = handle
export const PATCH = handle
export const DELETE = handle
export const HEAD = handle
export const OPTIONS = handle

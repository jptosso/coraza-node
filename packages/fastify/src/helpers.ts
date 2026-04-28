// Internal helpers for @coraza/fastify. NOT part of the public API —
// the main index intentionally does not re-export these. Tests import
// them directly via relative path.

const encoder = new TextEncoder()

export function headersOf(
  h: Record<string, string | string[] | number | undefined>,
  rawHeaders?: string[],
): [string, string][] {
  // Prefer `req.raw.rawHeaders` when available — it preserves
  // multi-value headers (two X-Forwarded-For lines, multiple Set-Cookie
  // entries, etc.) as distinct pairs. `req.headers` is the WHATWG-style
  // merged form that joins list-headers into one comma-separated
  // string, losing per-hop boundaries that CRS rules and audit logs
  // depend on.
  if (Array.isArray(rawHeaders) && rawHeaders.length >= 2) {
    const out: [string, string][] = []
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
      out.push([rawHeaders[i]!.toLowerCase(), rawHeaders[i + 1]!])
    }
    return out
  }
  const out: [string, string][] = []
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const item of v) out.push([k, String(item)])
    } else {
      out.push([k, String(v)])
    }
  }
  return out
}

export function serializeBody(body: unknown): Uint8Array | undefined {
  if (body === undefined || body === null) return undefined
  if (body instanceof Uint8Array) return body
  if (typeof body === 'string') return encoder.encode(body)
  try {
    return encoder.encode(JSON.stringify(body))
  } catch {
    return undefined
  }
}

export function payloadToBytes(payload: unknown): Uint8Array | undefined {
  if (payload instanceof Uint8Array) return payload
  if (typeof payload === 'string') return encoder.encode(payload)
  if (payload && typeof payload === 'object') {
    try {
      return encoder.encode(JSON.stringify(payload))
    } catch {
      return undefined
    }
  }
  return undefined
}

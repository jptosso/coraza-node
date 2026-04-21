// Internal helpers for @coraza/fastify. NOT part of the public API —
// the main index intentionally does not re-export these. Tests import
// them directly via relative path.

const encoder = new TextEncoder()

export function headersOf(
  h: Record<string, string | string[] | number | undefined>,
): [string, string][] {
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

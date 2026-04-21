import { Abi, encodeHeaders, utf8 } from './abi.js'
import type { Interruption, MatchedRule, RequestInfo, ResponseInfo } from './types.js'

const HEADER_BUF_INIT = 8192

/**
 * One transaction per HTTP request. Lifecycle:
 *
 *   processRequestBundle → maybe interrupt → processResponse →
 *     processResponseBody → processLogging → close
 *
 * Calls are synchronous and fast (< 1 ms for typical requests). The class
 * is stateful but cheap to construct; one instance per request.
 */
export class Transaction {
  #abi: Abi
  #id: number
  #closed = false
  #headerBuf = { current: new Uint8Array(HEADER_BUF_INIT) }

  constructor(abi: Abi, id: number) {
    this.#abi = abi
    this.#id = id
  }

  processConnection(addr: string, cport = 0, sport = 0): void {
    this.#ensureOpen()
    const a = utf8(addr)
    const aPtr = this.#writeMalloc(a)
    try {
      const rc = this.#abi.exports.tx_process_connection(this.#id, aPtr, a.length, cport, sport)
      this.#abi.check(rc, 'tx_process_connection')
    } finally {
      this.#abi.exports.host_free(aPtr)
    }
  }

  /**
   * True if `SecRuleEngine Off` is effective for this transaction. When true,
   * the adapter SHOULD skip the entire request — no headers, no body, no
   * response inspection. Cheapest possible early-exit.
   */
  isRuleEngineOff(): boolean {
    this.#ensureOpen()
    return this.#abi.exports.tx_is_rule_engine_off(this.#id) === 1
  }

  /**
   * True if Coraza will inspect the request body for this transaction. Use
   * this to short-circuit body serialization in your adapter — if the engine
   * has no rules that fire on this body (content-type / size / rule hints),
   * skip the body entirely.
   *
   * Call AFTER `processRequestBundle` — header rules can toggle accessibility.
   */
  isRequestBodyAccessible(): boolean {
    this.#ensureOpen()
    return this.#abi.exports.tx_is_request_body_accessible(this.#id) === 1
  }

  /**
   * Same as {@link isRequestBodyAccessible} but for the response body.
   * Prefer {@link isResponseBodyProcessable} unless you explicitly need the
   * looser "access allowed" check.
   */
  isResponseBodyAccessible(): boolean {
    this.#ensureOpen()
    return this.#abi.exports.tx_is_response_body_accessible(this.#id) === 1
  }

  /**
   * Stricter than {@link isResponseBodyAccessible}: also checks that the
   * response `Content-Type` is in Coraza's `SecResponseBodyMimeType` list.
   * Call AFTER `processResponse` (needs response headers to be set). Adapters
   * should use this to decide whether to stream the response body directly to
   * the client or tee it into Coraza's buffer.
   */
  isResponseBodyProcessable(): boolean {
    this.#ensureOpen()
    return this.#abi.exports.tx_is_response_body_processable(this.#id) === 1
  }

  /**
   * Fused call that runs the connection, URI, header, and body phases in
   * one WASM entry. Saves ~10 boundary crossings vs individual calls —
   * big win under `WAFPool` where every crossing is a MessagePort round-trip.
   *
   * Only usable when the request body is already buffered (Express's
   * body-parser runs before our middleware, so it always is in practice).
   */
  processRequestBundle(
    req: RequestInfo,
    body: Uint8Array | string | undefined,
  ): boolean {
    this.#ensureOpen()
    const bundle = encodeRequestBundle(req, body, this.#headerBuf)
    const ptr = this.#writeMalloc(bundle)
    try {
      const rc = this.#abi.exports.tx_process_request_bundle(this.#id, ptr, bundle.length)
      this.#abi.check(rc, 'tx_process_request_bundle')
      return rc === 1
    } finally {
      this.#abi.exports.host_free(ptr)
    }
  }

  /** Append a body chunk (for streaming). Call `finishRequestBody()` after the last chunk. */
  appendRequestBody(chunk: Uint8Array): void {
    this.#ensureOpen()
    if (chunk.length === 0) return
    const ptr = this.#writeMalloc(chunk)
    try {
      this.#abi.check(
        this.#abi.exports.tx_append_request_body(this.#id, ptr, chunk.length),
        'tx_append_request_body',
      )
    } finally {
      this.#abi.exports.host_free(ptr)
    }
  }

  finishRequestBody(): boolean {
    this.#ensureOpen()
    const rc = this.#abi.exports.tx_process_request_body_finish(this.#id)
    this.#abi.check(rc, 'tx_process_request_body_finish')
    return rc === 1
  }

  /** Process response status + headers. Returns true on interruption. */
  processResponse(res: ResponseInfo): boolean {
    this.#ensureOpen()
    const pkt = encodeHeaders(res.headers, this.#headerBuf)
    const proto = utf8(res.protocol ?? 'HTTP/1.1')
    const pktPtr = this.#writeMalloc(pkt)
    const protoPtr = this.#writeMalloc(proto)
    try {
      const rc = this.#abi.exports.tx_process_response_headers(
        this.#id,
        res.status,
        pktPtr,
        pkt.length,
        protoPtr,
        proto.length,
      )
      this.#abi.check(rc, 'tx_process_response_headers')
      return rc === 1
    } finally {
      this.#abi.exports.host_free(pktPtr)
      this.#abi.exports.host_free(protoPtr)
    }
  }

  processResponseBody(body?: Uint8Array | string): boolean {
    this.#ensureOpen()
    const bytes = typeof body === 'string' ? utf8(body) : body ?? new Uint8Array(0)
    if (bytes.length === 0) {
      const rc = this.#abi.exports.tx_process_response_body(this.#id, 0, 0)
      this.#abi.check(rc, 'tx_process_response_body')
      return rc === 1
    }
    const ptr = this.#writeMalloc(bytes)
    try {
      const rc = this.#abi.exports.tx_process_response_body(this.#id, ptr, bytes.length)
      this.#abi.check(rc, 'tx_process_response_body')
      return rc === 1
    } finally {
      this.#abi.exports.host_free(ptr)
    }
  }

  appendResponseBody(chunk: Uint8Array): void {
    this.#ensureOpen()
    if (chunk.length === 0) return
    const ptr = this.#writeMalloc(chunk)
    try {
      this.#abi.check(
        this.#abi.exports.tx_append_response_body(this.#id, ptr, chunk.length),
        'tx_append_response_body',
      )
    } finally {
      this.#abi.exports.host_free(ptr)
    }
  }

  finishResponseBody(): boolean {
    this.#ensureOpen()
    const rc = this.#abi.exports.tx_process_response_body_finish(this.#id)
    this.#abi.check(rc, 'tx_process_response_body_finish')
    return rc === 1
  }

  /** Returns the current interruption, or null. Check after each process*() call. */
  interruption(): Interruption | null {
    this.#ensureOpen()
    if (this.#abi.exports.tx_has_interrupt(this.#id) === 0) return null
    const packed = this.#abi.exports.tx_get_interrupt(this.#id)
    if (packed === 0n) return null
    const { ptr, len } = this.#abi.unpackSlice(packed)
    return JSON.parse(this.#abi.readString(ptr, len)) as Interruption
  }

  /** All rules that matched in this transaction (interrupted or not). */
  matchedRules(): MatchedRule[] {
    this.#ensureOpen()
    const packed = this.#abi.exports.tx_get_matched_rules(this.#id)
    if (packed === 0n) return []
    const { ptr, len } = this.#abi.unpackSlice(packed)
    return JSON.parse(this.#abi.readString(ptr, len)) as MatchedRule[]
  }

  /** Emit audit logs. Idempotent; also called on close(). */
  processLogging(): void {
    if (this.#closed) return
    this.#abi.check(this.#abi.exports.tx_process_logging(this.#id), 'tx_process_logging')
  }

  /** Release the WASM transaction slot. Idempotent. */
  close(): void {
    if (this.#closed) return
    this.#closed = true
    this.#abi.exports.tx_destroy(this.#id)
  }

  /**
   * Finalise the current transaction (audit log + close) and replace it
   * with a fresh one on the same WAF, keeping this handle valid. Use
   * when you want a new transaction without the allocation cost of
   * `waf.newTransaction()` — e.g. per-connection HTTP/1.1 keep-alive
   * loops, or a worker processing back-to-back requests.
   *
   * Throws if the transaction has already been closed or if the owning
   * WAF has been destroyed.
   */
  reset(): void {
    this.#ensureOpen()
    const rc = this.#abi.exports.tx_reset(this.#id)
    this.#abi.check(rc, 'tx_reset')
  }

  get closed(): boolean {
    return this.#closed
  }

  #ensureOpen(): void {
    if (this.#closed) throw new Error('coraza: transaction is closed')
  }

  /** Allocate a WASM buffer and copy `bytes` into it. Caller MUST free. */
  #writeMalloc(bytes: Uint8Array): number {
    if (bytes.length === 0) return 0
    const ptr = this.#abi.exports.host_malloc(bytes.length)
    if (ptr === 0) throw new Error('coraza: OOM allocating input buffer')
    this.#abi.writeAt(ptr, bytes)
    return ptr
  }
}

const bundleEncoder = new TextEncoder()

// Module-scoped scratch for short string encodings inside encodeRequestBundle.
// `Buffer.allocUnsafe` skips zero-fill; we only ever expose the exact byte
// ranges we wrote via `subarray`, so the uninitialised tail never leaks into
// the bundle. 64 KiB comfortably fits method (clipped 255) + proto (clipped
// 255) + addr (clipped 65535) + a typical URL. If the URL is oversize the
// encode falls back to a fresh Buffer.
const SCRATCH_CAP = 65536
const scratchBuf = Buffer.allocUnsafe(SCRATCH_CAP)

// Truncate a scratch-Buffer slice at `maxBytes` without splitting a multi-byte
// character. The WAF needs to evaluate *something* even if the field was
// attacker-inflated; throwing would let the adapter's catch→next() path
// turn the request into an unintended bypass.
function truncateUtf8(b: Uint8Array, maxBytes: number): Uint8Array {
  if (b.length <= maxBytes) return b
  let end = maxBytes
  // Step back over any continuation bytes (10xxxxxx) so we don't split a
  // codepoint; 4 bytes is the UTF-8 max so at most 3 steps.
  while (end > 0 && (b[end]! & 0xc0) === 0x80) end--
  return b.subarray(0, end)
}

// Encode `s` into a shared scratch Buffer at `offset`, returning the written
// byte length. Falls back to `bundleEncoder.encode` when the scratch can't
// hold the worst-case (4 × s.length) output — rare for short fields.
function writeScratch(s: string, offset: number): { bytes: Uint8Array; len: number } {
  const worstCase = s.length * 4
  if (offset + worstCase > SCRATCH_CAP) {
    const fresh = bundleEncoder.encode(s)
    return { bytes: fresh, len: fresh.length }
  }
  const len = scratchBuf.write(s, offset, 'utf8')
  return { bytes: scratchBuf.subarray(offset, offset + len), len }
}

/**
 * Pack connection+URI+headers+body into the compact binary bundle format
 * that `tx_process_request_bundle` decodes on the WASM side. See wasm/bundle.go
 * for the layout spec — keep these in lockstep.
 */
export function encodeRequestBundle(
  req: RequestInfo,
  body: Uint8Array | string | undefined,
  headerBuf?: { current: Uint8Array },
): Uint8Array {
  // Clip oversize fields rather than throw. Throwing would let the
  // adapter's catch-and-next() fallback turn a crafted-long-method
  // request into a WAF bypass. Clipping keeps the request evaluated.
  // These limits are an order of magnitude above anything legitimate
  // (method="PROPFIND" = 8 bytes, proto="HTTP/1.1" = 8 bytes).
  //
  // We lay the four short strings end-to-end in the module scratch Buffer
  // to skip four TextEncoder allocations per request. Each `writeScratch`
  // returns a subarray over exactly the bytes it wrote — nothing else
  // from the uninitialised scratch is ever read or copied out.
  let off = 0
  const methodEnc = writeScratch(req.method, off)
  off += methodEnc.len
  const method = truncateUtf8(methodEnc.bytes, 255)

  const protoEnc = writeScratch(req.protocol ?? 'HTTP/1.1', off)
  off += protoEnc.len
  const proto = truncateUtf8(protoEnc.bytes, 255)

  const addrEnc = writeScratch(req.remoteAddr ?? '', off)
  off += addrEnc.len
  const addr = truncateUtf8(addrEnc.bytes, 65535)

  const urlEnc = writeScratch(req.url, off)
  const url = urlEnc.bytes

  const cport = (req.remotePort ?? 0) & 0xffff
  const sport = (req.serverPort ?? 0) & 0xffff

  const hdrPkt = encodeHeaders(req.headers, headerBuf)

  const bodyBytes =
    typeof body === 'string' ? bundleEncoder.encode(body) : (body ?? new Uint8Array(0))

  const total =
    2 + addr.length + // addr
    2 + 2 + // cport + sport
    1 + method.length +
    1 + proto.length +
    4 + url.length +
    4 + hdrPkt.length +
    4 + bodyBytes.length

  // allocUnsafe: every byte of `outBuf[0..total)` is overwritten below before
  // we `subarray` it out, so the uninitialised backing memory never surfaces.
  const outBuf = Buffer.allocUnsafe(total)
  const out = new Uint8Array(outBuf.buffer, outBuf.byteOffset, total)
  const view = new DataView(outBuf.buffer, outBuf.byteOffset, total)
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

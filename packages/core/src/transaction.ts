import { Abi, encodeHeaders, utf8 } from './abi.js'
import type { Interruption, MatchedRule, RequestInfo, ResponseInfo } from './types.js'

const HEADER_BUF_INIT = 8192

/**
 * One transaction per HTTP request. Lifecycle:
 *
 *   processConnection → processRequest → (optional) processRequestBody →
 *     maybe interrupt → processResponse → processResponseBody →
 *     processLogging → close
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
   * Process the full request line + headers. Returns `true` if Coraza raised
   * an interruption and the caller should block.
   */
  processRequest(req: RequestInfo): boolean {
    this.#ensureOpen()
    if (req.remoteAddr !== undefined) {
      this.processConnection(req.remoteAddr, req.remotePort ?? 0, req.serverPort ?? 0)
    }

    const method = utf8(req.method)
    const url = utf8(req.url)
    const proto = utf8(req.protocol ?? 'HTTP/1.1')
    const methodPtr = this.#writeMalloc(method)
    const urlPtr = this.#writeMalloc(url)
    const protoPtr = this.#writeMalloc(proto)
    try {
      this.#abi.check(
        this.#abi.exports.tx_process_uri(
          this.#id,
          methodPtr,
          method.length,
          urlPtr,
          url.length,
          protoPtr,
          proto.length,
        ),
        'tx_process_uri',
      )
    } finally {
      this.#abi.exports.host_free(methodPtr)
      this.#abi.exports.host_free(urlPtr)
      this.#abi.exports.host_free(protoPtr)
    }

    const pkt = encodeHeaders(req.headers, this.#headerBuf)
    const pktPtr = this.#writeMalloc(pkt)
    try {
      const rc = this.#abi.exports.tx_process_request_headers(this.#id, pktPtr, pkt.length)
      this.#abi.check(rc, 'tx_process_request_headers')
      return rc === 1
    } finally {
      this.#abi.exports.host_free(pktPtr)
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
   * skip `processRequestBody` entirely.
   *
   * Call AFTER `processRequest` — header rules can toggle accessibility.
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

  /** Process the full request body in one shot. Returns true on interruption. */
  processRequestBody(body?: Uint8Array | string): boolean {
    this.#ensureOpen()
    const bytes = typeof body === 'string' ? utf8(body) : body ?? new Uint8Array(0)
    if (bytes.length === 0) {
      const rc = this.#abi.exports.tx_process_request_body(this.#id, 0, 0)
      this.#abi.check(rc, 'tx_process_request_body')
      return rc === 1
    }
    const ptr = this.#writeMalloc(bytes)
    try {
      const rc = this.#abi.exports.tx_process_request_body(this.#id, ptr, bytes.length)
      this.#abi.check(rc, 'tx_process_request_body')
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

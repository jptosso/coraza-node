// Low-level bindings to the Coraza WASM module. See wasm/ABI.md.
//
// This file is intentionally thin: it wraps each export with a typed
// function, handles memory view invalidation, and turns failure codes
// into thrown errors. Higher-level ergonomics (Transaction, WAF classes)
// live in transaction.ts / waf.ts.

export const ABI_MAJOR = 1

export interface CorazaExports {
  memory: WebAssembly.Memory

  abi_version(): number
  last_error(): bigint

  host_malloc(size: number): number
  host_free(ptr: number): void
  scratch_ptr(): number
  scratch_cap(): number

  waf_create(cfgPtr: number, cfgLen: number): number
  waf_destroy(id: number): void

  tx_create(wafId: number): number
  tx_destroy(id: number): void
  tx_has_interrupt(id: number): number
  tx_is_rule_engine_off(id: number): number
  tx_is_request_body_accessible(id: number): number
  tx_is_response_body_accessible(id: number): number
  tx_is_response_body_processable(id: number): number

  tx_process_connection(
    id: number,
    addrPtr: number,
    addrLen: number,
    cport: number,
    sport: number,
  ): number
  tx_process_uri(
    id: number,
    methodPtr: number,
    methodLen: number,
    uriPtr: number,
    uriLen: number,
    protoPtr: number,
    protoLen: number,
  ): number
  tx_process_request_headers(id: number, pktPtr: number, pktLen: number): number
  tx_process_request_body(id: number, bodyPtr: number, bodyLen: number): number
  tx_append_request_body(id: number, chunkPtr: number, chunkLen: number): number
  tx_process_request_body_finish(id: number): number
  tx_process_response_headers(
    id: number,
    status: number,
    pktPtr: number,
    pktLen: number,
    protoPtr: number,
    protoLen: number,
  ): number
  tx_process_request_bundle(id: number, bundlePtr: number, bundleLen: number): number
  tx_process_response_body(id: number, bodyPtr: number, bodyLen: number): number
  tx_append_response_body(id: number, chunkPtr: number, chunkLen: number): number
  tx_process_response_body_finish(id: number): number
  tx_process_logging(id: number): number

  tx_get_interrupt(id: number): bigint
  tx_get_matched_rules(id: number): bigint
}

/**
 * Typed wrapper around the WASM instance. Owns no higher-level state —
 * construct one per module instance and pass to WAF/Transaction classes.
 *
 * Memory views are cached but automatically refreshed if linear memory
 * grows between calls (WASM can grow on malloc; DataView/Uint8Array
 * become invalid when `memory.buffer` is replaced).
 */
export class Abi {
  readonly exports: CorazaExports
  private bytesView: Uint8Array
  private bufferRef: ArrayBufferLike

  constructor(exports: CorazaExports) {
    this.exports = exports
    this.bufferRef = exports.memory.buffer
    this.bytesView = new Uint8Array(this.bufferRef)
    const v = exports.abi_version()
    const major = (v >>> 16) & 0xffff
    if (major !== ABI_MAJOR) {
      throw new Error(`incompatible Coraza WASM ABI: expected major ${ABI_MAJOR}, got ${major}`)
    }
  }

  /** Returns a live Uint8Array over the WASM memory. Refreshes on growth. */
  bytes(): Uint8Array {
    if (this.exports.memory.buffer !== this.bufferRef) {
      this.bufferRef = this.exports.memory.buffer
      this.bytesView = new Uint8Array(this.bufferRef)
    }
    return this.bytesView
  }

  /** Copy `src` into WASM memory starting at `dst`. */
  writeAt(dst: number, src: Uint8Array): void {
    this.bytes().set(src, dst)
  }

  /** Copy `len` bytes from WASM memory starting at `ptr` into a fresh Uint8Array. */
  read(ptr: number, len: number): Uint8Array {
    if (len === 0) return new Uint8Array(0)
    return this.bytes().slice(ptr, ptr + len)
  }

  /** Read a UTF-8 string from WASM memory. */
  readString(ptr: number, len: number): string {
    if (len === 0) return ''
    return decoder.decode(this.bytes().subarray(ptr, ptr + len))
  }

  /** Unpack a (ptr << 32) | len i64 return into `{ ptr, len }`. */
  unpackSlice(packed: bigint): { ptr: number; len: number } {
    return {
      ptr: Number(packed >> 32n),
      len: Number(packed & 0xffffffffn),
    }
  }

  /** Read the last error string (if any). Clears on read per ABI contract. */
  lastError(): string {
    const packed = this.exports.last_error()
    if (packed === 0n) return ''
    const { ptr, len } = this.unpackSlice(packed)
    return this.readString(ptr, len)
  }

  /** Throw if rc is negative, attaching last_error as the cause. */
  check(rc: number, op: string): void {
    if (rc < 0) {
      const msg = this.lastError() || 'unknown error'
      throw new Error(`${op}: ${msg}`)
    }
  }
}

const decoder = new TextDecoder('utf-8', { fatal: false })

/**
 * Build the compact binary header packet described in ABI.md.
 *
 *   [count: u32][name_len: u32][name][value_len: u32][value]...
 *
 * Reuses `buf` when provided to avoid per-request allocation. Returns the
 * number of bytes written. Grows `buf` by reallocation only if undersized;
 * callers should size a persistent buffer to ≥8 KiB for typical requests.
 */
export function encodeHeaders(
  headers: Iterable<readonly [string, string]>,
  buf?: { current: Uint8Array },
): Uint8Array {
  // Two-pass to size the packet: cheap compared to actual WASM call.
  const entries: { n: Uint8Array; v: Uint8Array }[] = []
  let total = 4 // count
  for (const [name, value] of headers) {
    const n = encoder.encode(name)
    const v = encoder.encode(value)
    entries.push({ n, v })
    total += 4 + n.length + 4 + v.length
  }

  let out: Uint8Array
  if (buf && buf.current.length >= total) {
    out = buf.current.subarray(0, total)
  } else {
    out = new Uint8Array(total)
    if (buf) buf.current = out
  }

  const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
  view.setUint32(0, entries.length, true)
  let off = 4
  for (const { n, v } of entries) {
    view.setUint32(off, n.length, true)
    off += 4
    out.set(n, off)
    off += n.length
    view.setUint32(off, v.length, true)
    off += 4
    out.set(v, off)
    off += v.length
  }
  return out
}

const encoder = new TextEncoder()

/** Encode a JS string to UTF-8 without extra copies beyond what TextEncoder does. */
export function utf8(s: string): Uint8Array {
  return encoder.encode(s)
}

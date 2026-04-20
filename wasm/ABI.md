# coraza-node WASM ABI (v1)

This document defines the stable binary interface between the JavaScript host
(Node.js) and the TinyGo-compiled Coraza WASM module.

Design goals, in priority order:

1. **Zero-copy on the hot path.** Request bodies and headers are written once
   into WASM linear memory and never copied to an intermediate buffer.
2. **One call per request phase.** Full header sets are transferred in a single
   call using a compact length-prefixed binary format — no JSON parsing.
3. **Fast path returns i32.** The common "is this request clean?" check is a
   single i32 ≥ 0 branch.
4. **Packed pointers.** When a function returns both a pointer and a length,
   they are packed into a single `i64` (`(ptr << 32) | len`). This halves the
   call overhead vs the two-return ABI TinyGo otherwise requires.
5. **Scratch buffer.** The host can pre-allocate a single buffer at init and
   reuse it across calls, avoiding per-call `alloc` / `free` churn.
6. **Transaction pool.** Transactions are opaque IDs; the runtime may reuse IDs
   after `tx_destroy`. The host should not cache IDs across `waf_destroy`.

All integer arguments and returns are little-endian (WASM default). Strings
are UTF-8. The module is compiled `-target=wasi` so `fd_write` (stdout/stderr)
is available for diagnostics.

---

## Memory management

| Export | Signature | Semantics |
| --- | --- | --- |
| `malloc` | `(size: i32) -> i32` | Allocate `size` bytes in WASM memory. Returns pointer or `0` on OOM. |
| `free` | `(ptr: i32) -> ()` | Release a buffer previously returned by `malloc`. |
| `scratch_ptr` | `() -> i32` | Address of the persistent scratch buffer. Valid for the module lifetime. |
| `scratch_cap` | `() -> i32` | Capacity of the scratch buffer in bytes (default 64 KiB, may grow). |
| `memory` | (exported) | The module's linear memory. The host reads/writes directly via `new Uint8Array(memory.buffer, ptr, len)`. |

The scratch buffer MUST NOT be used to hold state across calls — its contents
become undefined at the next export invocation. For data that must survive
(e.g. long-lived config strings), use `malloc`.

---

## WAF lifecycle

### `waf_create(cfg_ptr: i32, cfg_len: i32) -> i32`

Create a WAF from SecLang directives. Returns a positive `waf_id` on success,
`-1` on failure (call `last_error` for details).

- `cfg_ptr` / `cfg_len`: UTF-8 SecLang configuration. Typically:
  `Include @coraza.conf-recommended\nInclude @crs-setup.conf\nInclude @owasp_crs/*.conf\nSecRuleEngine On`

CRS files (the `@`-prefixed paths above) are resolved via an embedded `fs.FS`
supplied by the `coraza-coreruleset` Go module — they ship inside the WASM.

### `waf_destroy(waf_id: i32) -> ()`

Free a WAF. All outstanding transactions created from it become invalid;
the host is responsible for destroying them first.

---

## Transaction lifecycle

### `tx_create(waf_id: i32) -> i32`

Create a new transaction. Returns a positive `tx_id`, or `-1` on error.

### `tx_destroy(tx_id: i32) -> ()`

Runs `ProcessLogging` (if not already run), calls `tx.Close()`, and releases
the slot. Idempotent.

### `tx_reset(tx_id: i32) -> i32` *(optional, post-v1)*

Resets a transaction for reuse without allocating a new one. Currently
`tx_destroy + tx_create` is used; this export is reserved.

---

## Request / response processing

All `tx_process_*` functions return:

- `0` — no interruption; continue processing
- `1` — interrupted; the host should fetch the interruption via `tx_get_interrupt`
- `-1` — error; call `last_error`

### `tx_process_connection(tx: i32, addr_ptr: i32, addr_len: i32, cport: i32, sport: i32) -> i32`

Sets the connection 4-tuple. `addr_ptr`/`addr_len` is the client IP as UTF-8
(e.g. `"203.0.113.5"`). `cport` / `sport` are client/server ports.

### `tx_process_uri(tx: i32, method_ptr: i32, method_len: i32, uri_ptr: i32, uri_len: i32, proto_ptr: i32, proto_len: i32) -> i32`

Supplies the request line. Must be called before `tx_process_request_headers`.

### `tx_process_request_headers(tx: i32, pkt_ptr: i32, pkt_len: i32) -> i32`

Header packet format (all integers little-endian u32):

```
[count: u32]
repeat count times:
  [name_len: u32][name_bytes...]
  [value_len: u32][value_bytes...]
```

Rationale: this is faster than JSON to both produce in JS (typed-array writes)
and consume in Go (no parser). Roughly 3-5× faster than `JSON.parse` for a
typical browser header set.

### `tx_process_request_body(tx: i32, body_ptr: i32, body_len: i32) -> i32`

Writes the entire request body at once. For streaming bodies, use the
chunked variant.

### `tx_append_request_body(tx: i32, chunk_ptr: i32, chunk_len: i32) -> i32`

Appends a body chunk. Call `tx_process_request_body_finish` when done.

### `tx_process_request_body_finish(tx: i32) -> i32`

Signals end-of-body; runs `ProcessRequestBody`.

### `tx_process_response_headers(tx: i32, status: i32, pkt_ptr: i32, pkt_len: i32, proto_ptr: i32, proto_len: i32) -> i32`

Same packet format as request headers.

### `tx_process_response_body(tx: i32, body_ptr: i32, body_len: i32) -> i32`

### `tx_append_response_body(tx: i32, chunk_ptr: i32, chunk_len: i32) -> i32`

### `tx_process_response_body_finish(tx: i32) -> i32`

### `tx_process_logging(tx: i32) -> i32`

Emits audit logs for the transaction. Idempotent; called automatically by
`tx_destroy` if not already invoked.

---

## Inspecting results

### `tx_has_interrupt(tx: i32) -> i32`

Returns `1` if an interruption has been raised on this transaction, else `0`.
Host SHOULD short-circuit with this before calling `tx_get_interrupt`.

### `tx_is_rule_engine_off(tx: i32) -> i32`

Returns `1` if `SecRuleEngine Off` is effective for this transaction. When
true, the host SHOULD short-circuit the entire request — no headers, no body,
no response inspection. This is the cheapest possible skip and should be the
first check after `tx_create`.

### `tx_is_request_body_accessible(tx: i32) -> i32`
### `tx_is_response_body_accessible(tx: i32) -> i32`

Returns `1` if Coraza's current configuration will inspect the request/response
body for this transaction, else `0`. **The host MUST gate body ingestion on
these flags** — if the body is inaccessible, skip the `tx_process_*_body`
calls entirely. This is the single biggest perf win: skipping body serialization
+ a WASM roundtrip for requests whose content-type or size Coraza ignores.

Check AFTER `tx_process_request_headers` (the request flag may change in
response to header rules) and AFTER `tx_process_response_headers` for the
response flag.

### `tx_is_response_body_processable(tx: i32) -> i32`

Stricter than `tx_is_response_body_accessible`: also checks that the response
`Content-Type` matches `SecResponseBodyMimeType`. Use this **after**
`tx_process_response_headers` to decide whether to stream the response body
straight to the client (skip processing) or tee it into Coraza's buffer.
Most adapters should prefer this over the plain `accessible` check on the
response path.

### `tx_get_interrupt(tx: i32) -> i64`

Returns a packed `(ptr << 32) | len` pointing into the scratch buffer. The
bytes at that region are a JSON object:

```json
{
  "ruleId": 942100,
  "action": "deny",
  "status": 403,
  "data": "Matched \"Operator `Rx' with parameter ..."
}
```

Returns `0` if no interruption. The JSON layout is fixed; callers should
tolerate additional fields in future versions (forward-compatible).

Why JSON here (and not the compact format)? This path is cold — it fires once
per blocked request — and the fields are small and variable. JSON parse cost
is negligible compared to the serialization overhead of a custom codec.

### `tx_get_matched_rules(tx: i32) -> i64`

Returns `(ptr << 32) | len` of a JSON array of every rule that matched,
whether or not the transaction was interrupted. Useful in detect-only mode
for reporting. Returns `0` if no rules matched.

### `last_error() -> i64`

Returns the packed pointer to the last error string set by any failing call.
Returns `0` if no error. Error is cleared on read.

---

## Host imports

The module expects these imports under the `env` namespace:

| Import | Signature | Purpose |
| --- | --- | --- |
| `env.log` | `(level: i32, msg_ptr: i32, msg_len: i32) -> ()` | Forwards Coraza audit/error log lines to the host logger. Level: 0=debug, 1=info, 2=warn, 3=error. |
| `env.now_millis` | `() -> i64` | Current wall clock in ms. (TinyGo's WASI time is coarse; host-provided is optional.) |

`wasi_snapshot_preview1` imports are also required (standard TinyGo WASI output).

---

## Versioning

The ABI version is exported as a constant:

### `abi_version() -> i32`

Returns an integer. Layout: `major << 16 | minor`. v1 of this document is
`0x00010000` (65536).

Breaking changes bump `major`. The host MUST check `abi_version` on load and
refuse to run if the major doesn't match.

---

## Performance notes

- **Header batching**: a single 8 KiB packet fits ~40 typical headers. Even
  large cookie headers stay under the scratch buffer budget.
- **Body handling**: Coraza's default body limit is 1 MiB; above that, requests
  are rejected before rules run. Keep the buffer strategy simple — one write
  is optimal for bodies up to 128 KiB; chunked appends help only for streaming
  protocols (SSE, large uploads).
- **Transaction cost**: `tx_create` allocates Coraza's internal state; aim to
  keep one transaction per request. Pooling `tx_create`/`tx_destroy` across
  requests is **not** safe — Coraza's transaction state is not reset-capable.
- **Instance sharing**: a single WASM module instance is single-threaded. For
  concurrency, run N instances under `worker_threads` (recommended: one per
  CPU core). Instance startup is ~5-20 ms, so amortize by keeping them warm.
- **Regex perf**: TinyGo compiles `regexp` to a portable but slower engine
  than host-native. Enabling `@coraza/wasilibs`-equivalent operators in Coraza
  builds is under evaluation for v2.

---

## Example call sequence (request pass-through)

```
waf_id = waf_create(cfg_ptr, cfg_len)
tx_id  = tx_create(waf_id)

tx_process_connection(tx_id, ip, ip_len, cport, sport)
tx_process_uri(tx_id, "GET", 3, "/health", 7, "HTTP/1.1", 8)
tx_process_request_headers(tx_id, pkt, pkt_len)
tx_has_interrupt(tx_id)                 // 0 — pass
// ... request runs in Node ...
tx_process_response_headers(tx_id, 200, pkt, pkt_len, "HTTP/1.1", 8)
tx_has_interrupt(tx_id)                 // 0 — pass
tx_process_logging(tx_id)
tx_destroy(tx_id)
```

Blocked request — same sequence up to the point of interruption, then:

```
tx_has_interrupt(tx_id)                 // 1
packed = tx_get_interrupt(tx_id)
ptr    = Number(packed >> 32n)
len    = Number(packed & 0xffffffffn)
json   = decode(ptr, len)
// respond with json.status and json.data in detect logs
tx_process_logging(tx_id)
tx_destroy(tx_id)
```

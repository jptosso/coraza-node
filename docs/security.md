# Security notes for coraza-node

This is a WAF — security correctness trumps everything else in this repo.
If you're working on perf, read this first so your changes don't land an
attack escape.

## Priority

1. **Correctness** — the WAF must evaluate every request against every
   configured rule and block what CRS (or your custom rules) says to block.
2. **Availability** — the WAF shouldn't crash the host server or loop forever.
3. **Performance** — throughput and latency.

Never trade (1) for (3) silently. An opt-in, clearly-documented knob that
allows a user to accept a risk (e.g. `inspectResponse: false` to skip
phase 4) is fine. A perf optimization that happens to skip some attacks
without warning is a bug.

## Threat model

The WAF sits inside the application process. Trust assumptions:

- Node.js process is trusted. Attackers interact via HTTP requests, not
  by running code in the same process.
- The Coraza WASM is trusted (we compile it from a pinned upstream).
- The CRS rule set is trusted (we embed a pinned version).
- `worker_threads` are trusted (same OS process, shared memory semantics).
- The host running Node is trusted for resource exhaustion (we don't
  try to protect against a co-tenant DoS'ing the box).

We protect against:

- Crafted HTTP requests trying to bypass detection (SQLi / XSS / LFI /
  RCE / etc. payloads).
- Crafted requests designed to exploit WAF implementation bugs (oversize
  fields, malformed UTF-8, unusual methods) to reach handlers unfiltered.
- WAF crashes/panics becoming silent bypasses (fail-closed by default).

We don't protect against:

- Regex ReDoS from within V8's Irregexp engine (see caveat below).
- Denial of service via legitimately large or numerous requests (use
  upstream rate limits).
- Attacks on handlers that succeed despite detection — the WAF raises
  the bar, it's not a substitute for secure code.

## Fail-closed checklist

- [x] Adapter middleware `catch` turns errors into 503 block responses
  (`onWAFError: 'block'` default). `onWAFError: 'allow'` is opt-in for
  availability-over-security deployments.
- [x] `newTransaction` failure also fails closed.
- [x] Bundle encoder **clips** oversize fields instead of throwing —
  throwing would let the catch path bypass the WAF.
- [x] `extractBody` returns `undefined` on unserializable inputs rather
  than throwing — body phase still runs with empty body (phase 2 still
  evaluates anomaly score).
- [x] Response inspection (`inspectResponse: true`) uses a sync `WAF`,
  not a `WAFPool`. If a user combines them the adapter logs and skips
  the response hooks rather than silently running them unawaited.
- [x] Host-regex compile failures fall back to Go's `regexp.Compile`
  inside the WASM. A pattern that neither engine can compile still
  surfaces as a WAF init error.

## Known caveats

### V8 RegExp vs Go regex (host-regex merge)

**The `@rx` operator routes through V8 Irregexp by default.** V8 is
backtracking; Go's stdlib regex is Thompson-NFA (RE2-style, linear time).
This means:

- **ReDoS potential**. A pattern authored to be safe under Go's RE2
  might be ReDoS-exploitable under V8's backtracking. CRS rules are
  careful about this, but CRS has shipped ReDoS-vulnerable patterns
  before (historical CVEs).
- **Mitigation today**: none at runtime — V8 has no regex timeout API.
  Mitigation is an operational concern: run the WAF in a worker pool
  (`WAFPool`) so one hung worker doesn't kill throughput, and monitor
  worker liveness.
- **If you need RE2 semantics back**, comment out the `registerHostRX()`
  call in `wasm/main.go::init()`. Coraza's built-in rx operator will take
  over with full RE2-linear-time guarantees, at the cost of the
  host-regex perf win.

### Unicode case-insensitive (`(?i)`)

PCRE `i` does full Unicode case folding. JS `i` without the `u` flag
does only ASCII folding. Our `translatePattern` doesn't auto-add `u`
because CRS patterns aren't authored with Unicode classes in mind.

**Implication**: an attacker encoding an attack payload in non-ASCII
case variations (e.g. Turkish dotted/dotless İ) could evade a
case-insensitive CRS rule under host-regex that it would NOT evade under
Coraza's original Go regex engine.

**Mitigation**: CRS already lowercases input via `t:lowercase` before
rules that depend on case-insensitive matching. As long as your rule
chain includes that transformation, the byte-level input is already
ASCII-lowercased and the difference doesn't matter.

### UTF-8 encoding of request body

Coraza's Go side reads bytes. Our host-regex imports decode bytes to JS
strings via `TextDecoder` (UTF-8, `fatal: false`). Invalid UTF-8 bytes
become U+FFFD replacement chars.

**Implication**: a payload with malformed UTF-8 sequences could appear
different to V8 RegExp (post-decode) vs Coraza's Go engine (pre-decode,
byte-level).

**Mitigation**: host-regex *match result* is combined with Go fallback
for Capturing rules, so the byte-level engine still runs for those.
For non-capturing rules, this is a theoretical gap — no known exploit.
If concerned, set `CORAZA_HOST_RX=off` to disable host-regex.

### Long methods / URLs / addresses

The bundle encoder clips oversize fields at 255 bytes (method, proto),
65535 bytes (remote addr), and leaves URLs uncapped (u32 length). This
is to keep the request evaluated even when fields are attacker-inflated,
rather than throwing (which historically would have bypassed).

**Implication**: a 10MB method name would be truncated to the first
255 bytes and the WAF would see only that prefix.

**Mitigation**: Express's HTTP parser already rejects oversize request
lines at ~64KB, long before the WAF is invoked. The clipping is
defense-in-depth.

### Prefilter accuracy (rxprefilter port)

The rxprefilter skips regex evaluation when required literals are
absent from the input. Bug class: the literal extractor might be wrong
— thinking a literal is required when it isn't — which would cause the
WAF to skip a regex that WOULD have matched.

**Mitigation**: the port is a literal copy of upstream Coraza
`internal/operators/rxprefilter.go` (coraza main branch). Upstream has
tests for this module (`rxprefilter_test.go`, `rxprefilter_crs_test.go`)
that our port doesn't ship yet.

**Follow-up**: port the rxprefilter tests and include them in our CI.
Tracked in [issue-tbd]. Until then, treat any new rxprefilter behavior
with suspicion; disable with a build-tag flag if a regression surfaces.

## Audit checklist for new perf changes

Before merging any perf-motivated change:

1. **Measure block rate, not just RPS.** Use `bench/k6/mixed.js` — it
   counts `blocked_attacks` and `missed_attacks` separately. Both
   numbers must either stay the same or improve.
2. **Check the adapter catch paths.** If any new code path throws,
   trace what the adapter `catch` block does. Does it fall back to
   `next()` silently? That's a bypass vector. Use clipping or
   fail-closed explicit blocks instead.
3. **Check default values.** Any new `onWAFError`-style option must
   default to the secure choice. Fast-paths that skip evaluation must
   be opt-in, not default-on.
4. **Look for regex engine substitution.** Any change that routes
   patterns through a different engine (host-regex, prefilter, etc.)
   must document the semantic differences in this file.
5. **Load-test with a real attack mix.** `k6 run bench/k6/mixed.js`
   includes SQLi/XSS/oversize scenarios. Don't just bench the happy path.

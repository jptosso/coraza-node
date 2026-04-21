---
'@coraza/core': minor
---

perf(pool): ship request bundles over a per-worker SharedArrayBuffer and Atomics.waitAsync handshake instead of structured-cloning each Uint8Array through the MessagePort. Oversized bundles fall back to the existing postMessage path so large bodies keep working end-to-end. UTF-8 clip semantics in `encodeRequestBundle` are preserved unchanged; the new sink-mode overload writes in place for the fast path but never throws into the adapter's catch→next() fallback. A 5 s timeout on the Atomics handshake surfaces as an error the adapter turns into a 503 fail-closed, so a hung worker can't become a bypass.

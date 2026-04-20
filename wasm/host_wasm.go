//go:build tinygo || wasm
// +build tinygo wasm

// Memory bridge helpers for the WASM/TinyGo target.
//
// ============================================================================
// unsafe USAGE AUDIT (v1)
// ============================================================================
// This file is the ONLY place in the codebase that uses `unsafe.Pointer` or
// `unsafe.Slice`. Every use is enumerated here with its invariants.
//
// 1. `readBytes(ptr, length)` — reconstructs a Go slice aliasing the WASM
//    linear-memory region at address `ptr`.
//      INVARIANT: `ptr` was produced by either (a) host pointer arithmetic
//                 against `WebAssembly.Memory.buffer`, (b) `host_malloc`, or
//                 (c) the `scratchBacking` global's address.
//      INVARIANT: `length >= 0 && ptr + length <= wasm memory bytes`.
//                 The host is contractually responsible; we hard-clamp against
//                 an implausibility ceiling (256 MiB).
//      LIFETIME : slice is valid ONLY for the current call. The host may
//                 overwrite the region on the next export invocation.
//
// 2. `scratchPtr()` — publishes `&scratchBacking[0]` as an int32.
//      INVARIANT: scratchBacking is a package-level fixed-size array, so its
//                 address is stable for the module lifetime.
//      INVARIANT: under WASI-32 the address always fits in 32 bits.
//
// 3. `hostMalloc(size)` — allocates a Go-backed byte slice and leaks its
//    pointer to the host.
//      INVARIANT: we pin the backing array in `alive` so the Go GC can't
//                 reclaim it while the host holds the raw pointer.
//      INVARIANT: `host_free(ptr)` is eventually called for every non-zero
//                 return. The TS layer wraps every malloc in a try/finally
//                 to enforce this.
//      DEFENSE : refuses allocations above 64 MiB — a legit host never
//                 needs that much (Coraza body limit is 1 MiB by default).
//
// 4. `writeScratch(b)` — packs the scratch pointer + len(b) into an i64.
//      INVARIANT: b is either (a) a slice already aliasing scratchBacking
//                 (zero-copy), or (b) any other slice, copied in first.
//      INVARIANT: `len(b) <= len(scratchBacking)` — hard-truncated on entry
//                 so a buggy caller can never write past the region.
// ============================================================================
//
// Non-goals:
//   - We DO NOT rely on any pointer-integer aliasing beyond WASI-32 flat
//     memory. Running this file on a 64-bit host would SIGSEGV — that's
//     why host_native.go exists for `go test`.
//   - We DO NOT use `unsafe.Slice` with a host-controlled length that wasn't
//     first bounds-checked against `WebAssembly.Memory.byteLength` on the
//     TS side. The 256 MiB ceiling here is a defense-in-depth against a
//     buggy or malicious host.

package main

import "unsafe"

// scratchBacking is the fixed backing store for short-lived outputs.
// Pointer is stable for the module lifetime, so the host caches it from
// scratch_ptr() once.
var scratchBacking [64 * 1024]byte

// scratchBuf aliases scratchBacking with a resettable length.
var scratchBuf = scratchBacking[:0]

// writeScratch copies b into the scratch backing store and returns a
// packed (ptr << 32) | len i64 for the host to read. Hard-truncates if b
// exceeds scratchBacking capacity.
func writeScratch(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	if len(b) > len(scratchBacking) {
		b = b[:len(scratchBacking)]
	}
	if &b[0] != &scratchBacking[0] {
		n := copy(scratchBacking[:], b)
		b = scratchBacking[:n]
	}
	ptr := uintptr(unsafe.Pointer(&scratchBacking[0]))
	return (int64(ptr) << 32) | int64(uint32(len(b)))
}

// readBytes reconstructs a Go byte slice from a WASM (ptr, len) pair.
// Zero-copy — the slice must not outlive the current call.
func readBytes(ptr, length int32) []byte {
	if ptr == 0 || length <= 0 {
		return nil
	}
	// Defense in depth: refuse implausibly large reads even if the host asks.
	const maxReasonable = 256 << 20 // 256 MiB
	if length > maxReasonable {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), int(length))
}

//export scratch_ptr
func scratchPtr() int32 {
	return int32(uintptr(unsafe.Pointer(&scratchBacking[0])))
}

//export scratch_cap
func scratchCap() int32 { return int32(len(scratchBacking)) }

// alivePool pins host-allocated slices so TinyGo's GC doesn't reclaim them
// while their int32 addresses are held by JS. A plain slice is safer than
// a map keyed on uintptr: TinyGo's conservative GC scans slices reliably,
// and we never have to hand the runtime a key that might not be there.
//
// Trade-off: hostFree is a no-op. We accept the leak — input buffers are
// tiny (header packets <8 KiB, bodies capped by Coraza's body limit). A
// long-running instance grows slowly and can be recycled by the worker pool.
var alivePool [][]byte

//export host_malloc
func hostMalloc(size int32) int32 {
	if size <= 0 {
		return 0
	}
	const maxAlloc = 64 << 20 // 64 MiB — well above Coraza's body limit
	if size > maxAlloc {
		return 0
	}
	p := make([]byte, size)
	alivePool = append(alivePool, p)
	return int32(uintptr(unsafe.Pointer(&p[0])))
}

//export host_free
func hostFree(ptr int32) {
	// No-op. See alivePool comment above.
	_ = ptr
}

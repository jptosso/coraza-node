//go:build !tinygo && !wasm
// +build !tinygo,!wasm

// Native (non-WASM) implementation of the memory bridge. Used only by
// `go test` — the production WASM build uses host_wasm.go, which relies
// on unsafe pointer arithmetic that's invalid on 64-bit hosts.
//
// Here we use a handle table: `ptrOf` stores a slice and returns a small
// int32 cookie; `readBytes` looks it up. The scratch buffer is still a
// real Go array but `scratch_ptr` returns a well-known cookie so host
// code round-trips correctly.

package main

import "sync"

var (
	nativeHandles   = map[int32][]byte{}
	nativeHandlesMu sync.Mutex
	nativeNextH     int32 = 100 // reserve 0..99 for special cookies
)

// scratch cookie so readBytes can detect scratch pointers and return
// scratchBacking directly (with the caller-supplied length).
const nativeScratchCookie int32 = 1

var scratchBacking [64 * 1024]byte
var scratchBuf = scratchBacking[:0]

// nativePin registers b in the handle table and returns its cookie.
// Exposed for tests in integration_test.go.
func nativePin(b []byte) int32 {
	if len(b) == 0 {
		return 0
	}
	nativeHandlesMu.Lock()
	defer nativeHandlesMu.Unlock()
	nativeNextH++
	id := nativeNextH
	nativeHandles[id] = b
	return id
}

// nativeUnpinAll clears every pinned slice.
func nativeUnpinAll() {
	nativeHandlesMu.Lock()
	defer nativeHandlesMu.Unlock()
	for k := range nativeHandles {
		delete(nativeHandles, k)
	}
	nativeNextH = 100
}

func writeScratch(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	if len(b) > 0 && &b[0] != &scratchBacking[0] {
		n := copy(scratchBacking[:], b)
		b = scratchBacking[:n]
	}
	// Pack (cookie, len). Host resolves via readBytes + nativeScratchCookie.
	return (int64(nativeScratchCookie) << 32) | int64(uint32(len(b)))
}

func readBytes(ptr, length int32) []byte {
	if ptr == 0 || length <= 0 {
		return nil
	}
	if ptr == nativeScratchCookie {
		return scratchBacking[:length]
	}
	nativeHandlesMu.Lock()
	defer nativeHandlesMu.Unlock()
	b, ok := nativeHandles[ptr]
	if !ok {
		return nil
	}
	if int(length) > len(b) {
		return b
	}
	return b[:length]
}

func scratchPtr() int32 { return nativeScratchCookie }
func scratchCap() int32 { return int32(len(scratchBacking)) }

func hostMalloc(size int32) int32 {
	if size <= 0 {
		return 0
	}
	return nativePin(make([]byte, size))
}

func hostFree(ptr int32) {
	nativeHandlesMu.Lock()
	delete(nativeHandles, ptr)
	nativeHandlesMu.Unlock()
}

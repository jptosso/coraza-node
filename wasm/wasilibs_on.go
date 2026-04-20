//go:build wasilibs
// +build wasilibs

// Opt-in wasilibs operators. Enabled with `-tags=wasilibs` on native Go
// builds (tests / benchmarks). NOT used in the TinyGo→WASM production
// build — TinyGo's linker can't handle wazero's internals and segfaults.
//
// Replaces Go stdlib regexp / aho-corasick / XSS with WASI-native Ragel
// and C-compiled-to-WASM implementations for a 3-9× speedup on body-phase
// rules. See bench_test.go for numbers.

package main

import wasilibs "github.com/corazawaf/coraza-wasilibs"

func init() {
	wasilibs.Register()
}

//go:build !tinygo && !wasm
// +build !tinygo,!wasm

// Native builds (go test) don't have a V8 RegExp engine to forward to,
// so host-regex is a no-op: Coraza falls back to its built-in stdlib
// regex operator. `hostrx.go` provides the real WASM-only replacement.
package main

func registerHostRX() {}

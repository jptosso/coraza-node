//go:build tinygo
// +build tinygo

// Use wasilibs' nottinygc (BDWGC-based) as the garbage collector under
// TinyGo. TinyGo's built-in conservative/leaking collectors can't handle
// Coraza + CRS's regex compilation; nottinygc does. This matches what
// coraza-proxy-wasm does in production.
//
// Requires `-gc=custom` + `-tags=custommalloc` on the TinyGo build line.

package main

import _ "github.com/wasilibs/nottinygc"

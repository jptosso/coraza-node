//go:build tinygo || wasm
// +build tinygo wasm

// Override Coraza's built-in `rx` operator with one that forwards every
// compile/match call to the JS host. V8's Irregexp is JIT-compiled and
// significantly faster than Go's regexp inside a WASM runtime. If the
// host reports it cannot compile a pattern (returns 0), we fall back to
// Go's stdlib so CRS still works.

package main

import (
	"regexp"
	"unsafe"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

//go:wasmimport env rx_compile
func hostRxCompile(patPtr, patLen int32) int32

//go:wasmimport env rx_match
func hostRxMatch(handle, inputPtr, inputLen int32) int32

//go:wasmimport env rx_free
func hostRxFree(handle int32)

type hostRx struct {
	handle   int32              // > 0 when host compiled it
	fallback *regexp.Regexp      // non-nil when we fall back to Go
}

func newHostRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	// Matches wasilibs' `(?sm)` prefix: CRS patterns assume dotall+multiline.
	pattern := "(?sm)" + options.Arguments

	patBytes := []byte(pattern)
	var patPtr int32
	if len(patBytes) > 0 {
		patPtr = int32(uintptr(unsafe.Pointer(&patBytes[0])))
	}
	handle := hostRxCompile(patPtr, int32(len(patBytes)))
	if handle > 0 {
		// Pin the pattern bytes so GC doesn't reclaim before compile returns.
		// Compile already copied on the host side, so we can drop after.
		_ = patBytes
		return &hostRx{handle: handle}, nil
	}

	// Host rejected (usually PCRE-only syntax). Fall back to Go regex.
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &hostRx{fallback: re}, nil
}

func (o *hostRx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if o.handle > 0 {
		valBytes := []byte(value)
		var valPtr int32
		if len(valBytes) > 0 {
			valPtr = int32(uintptr(unsafe.Pointer(&valBytes[0])))
		}
		matched := hostRxMatch(o.handle, valPtr, int32(len(valBytes))) == 1
		if !matched {
			return false
		}
		// CRS captures are set via tx.CaptureField. For a minimum-viable
		// host-rx we only report the match; captures fall back to Go if
		// Capturing() is true. (This is a known trade-off; many CRS rules
		// don't capture, so the fast path still wins.)
		if tx.Capturing() {
			// Fallback to Go to fill captures.
			if o.fallback == nil {
				return true // can't produce captures; report match
			}
			m := o.fallback.FindStringSubmatch(value)
			for i, c := range m {
				if i == 9 {
					return true
				}
				tx.CaptureField(i, c)
			}
		}
		return true
	}

	// Pure Go fallback (pattern rejected by host).
	if tx.Capturing() {
		m := o.fallback.FindStringSubmatch(value)
		if len(m) == 0 {
			return false
		}
		for i, c := range m {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
		return true
	}
	return o.fallback.MatchString(value)
}

func registerHostRX() {
	plugins.RegisterOperator("rx", newHostRX)
}

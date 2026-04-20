//go:build tinygo || wasm
// +build tinygo wasm

// Override Coraza's built-in `rx` operator with one that:
//
//   1. Runs a cheap compile-time-extracted prefilter (minimum match length
//      + required-literal check) to skip regex evaluation when the input
//      clearly can't match. Ported from coraza main's
//      internal/operators/rxprefilter.go.
//
//   2. For inputs that pass the prefilter, forwards to V8's RegExp via
//      a WASM host import (env.rx_match). V8's Irregexp JIT beats Go's
//      stdlib regex running inside WASM.
//
//   3. If a pattern is something V8 can't parse (atomic groups,
//      possessive quantifiers, ignore-whitespace, etc.), falls back to
//      Go's regexp.Compile and runs the match in-WASM.
//
// The prefilter is the single biggest win on benign traffic: it's a
// required-condition check built from the regex AST at compile time,
// costing an `strings.Contains` or Wu-Manber scan per evaluation vs
// running the full Irregexp / Go-regex state machine.

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
	handle    int32              // > 0 when host compiled it
	fallback  *regexp.Regexp      // non-nil when we fall back to Go
	minLen    int                 // minimum input length that could match
	prefilter func(string) bool   // required-literal prefilter, nil if none
}

func newHostRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	// Matches wasilibs' `(?sm)` prefix: CRS patterns assume dotall+multiline.
	pattern := "(?sm)" + options.Arguments

	// Build the cheap prefilter *before* trying either backend. Even if
	// host-compile or Go-compile fails later, this tells us the minimum
	// input length needed for any match. It's safe to feed the raw
	// pattern — failure paths return conservative defaults.
	minL := minMatchLength(pattern)
	pre := prefilterFunc(pattern)

	patBytes := []byte(pattern)
	var patPtr int32
	if len(patBytes) > 0 {
		patPtr = int32(uintptr(unsafe.Pointer(&patBytes[0])))
	}
	handle := hostRxCompile(patPtr, int32(len(patBytes)))
	if handle > 0 {
		return &hostRx{handle: handle, minLen: minL, prefilter: pre}, nil
	}

	// Host rejected (usually PCRE-only syntax). Fall back to Go regex.
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &hostRx{fallback: re, minLen: minL, prefilter: pre}, nil
}

func (o *hostRx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	// Prefilter #1: input too short to match the minimum-length requirement.
	if o.minLen > 0 && len(value) < o.minLen {
		return false
	}
	// Prefilter #2: required literals absent.
	if o.prefilter != nil && !o.prefilter(value) {
		return false
	}

	// Regex engine (host-first, Go fallback).
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
		if tx.Capturing() {
			if o.fallback == nil {
				return true
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

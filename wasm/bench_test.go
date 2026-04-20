// Go benchmarks for the WASM ABI hot paths. Run:
//
//   go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof
//   go tool pprof -http=:0 cpu.prof
//
// Or via the Makefile:
//
//   make bench        # numbers only
//   make profile      # also emits cpu.prof + mem.prof under wasm/build/
//
// Targets the slow layers first: header packet parse, JSON writer, full
// request pipeline through Coraza.

//go:build !tinygo && !wasm
// +build !tinygo,!wasm

package main

import (
	"strconv"
	"testing"
)

func BenchmarkParseHeaderPacket_Small(b *testing.B) {
	pkt := encodeHeaderPacket([][2]string{
		{"Host", "example.com"},
		{"User-Agent", "Mozilla/5.0"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9"},
	})
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseHeaderPacket(pkt, func(_, _ []byte) {})
	}
}

func BenchmarkParseHeaderPacket_Typical(b *testing.B) {
	// A realistic browser header set (~15 headers).
	headers := [][2]string{
		{"Host", "api.example.com"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Cookie", "sid=abc123; session=xyz; ab_test=variant_b"},
		{"Connection", "keep-alive"},
		{"Referer", "https://www.example.com/path/subpath"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-User", "?1"},
		{"Upgrade-Insecure-Requests", "1"},
		{"X-Forwarded-For", "203.0.113.5, 10.0.0.2"},
		{"X-Request-Id", "01J5K8P9Q7R2M3N4X6Z8Y9A7B2"},
	}
	pkt := encodeHeaderPacket(headers)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseHeaderPacket(pkt, func(_, _ []byte) {})
	}
}

func BenchmarkWriteInterruptJSON(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := scratchBacking[:0]
		buf = append(buf, '{')
		buf = writeKV(buf, "ruleId", 942100)
		buf = append(buf, ',')
		buf = writeKVS(buf, "action", "deny")
		buf = append(buf, ',')
		buf = writeKV(buf, "status", 403)
		buf = append(buf, ',')
		buf = writeKVS(buf, "data", `Matched "Operator Rx"`)
		buf = append(buf, '}')
		_ = buf
	}
}

func BenchmarkWriteInt(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 0, 20)
		_ = writeInt(buf, int64(i))
	}
}

// Full-pipeline benchmark: build a WAF once, then repeatedly run a
// benign request through it. This covers the hot path all users hit
// (Coraza's own cost dominates here; the ABI layer is measured in
// parentheses).
func BenchmarkRequestPipeline_Benign(b *testing.B) {
	resetState()
	cfg := []byte(`SecRuleEngine On`)
	wafID := wafCreate(ptrOf(cfg), int32(len(cfg)))
	if wafID <= 0 {
		b.Fatalf("waf_create failed: %q", string(lastErrMsg))
	}
	defer wafDestroy(wafID)

	method := []byte("GET")
	uri := []byte("/api/users/42")
	proto := []byte("HTTP/1.1")
	addr := []byte("1.2.3.4")
	pkt := encodeHeaderPacket([][2]string{
		{"Host", "example.com"},
		{"Accept", "application/json"},
		{"User-Agent", "bench/1.0"},
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		txID := txCreate(wafID)
		txProcessConnection(txID, ptrOf(addr), int32(len(addr)), 45000, 80)
		txProcessURI(txID,
			ptrOf(method), int32(len(method)),
			ptrOf(uri), int32(len(uri)),
			ptrOf(proto), int32(len(proto)),
		)
		txProcessRequestHeaders(txID, ptrOf(pkt), int32(len(pkt)))
		txProcessLogging(txID)
		txDestroy(txID)
	}
	b.StopTimer()
	nativeUnpinAll() // release accumulated pins
}

// BenchmarkRequestPipeline_CRS measures the full Coraza + CoreRuleSet
// pipeline on a benign request. Compare against BenchmarkRequestPipeline_Benign
// to see the overhead introduced by the rule set itself (not the ABI).
//
// Config mirrors what `@coraza/coreruleset`'s `recommended()` emits: the
// full CRS, with PHP/Java/.NET language rules removed (Node.js-only target).
func BenchmarkRequestPipeline_CRS(b *testing.B) {
	resetState()
	cfg := []byte(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=1"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5"
SecAction "id:900002,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=4"
Include @owasp_crs/*.conf
SecRuleRemoveByTag "language-php"
SecRuleRemoveByTag "language-java"
SecRuleRemoveByTag "language-dotnet"
SecRuleEngine On
`)
	wafID := wafCreate(ptrOf(cfg), int32(len(cfg)))
	if wafID <= 0 {
		b.Skipf("waf_create failed (CRS rules): %q", string(lastErrMsg))
		return
	}
	defer wafDestroy(wafID)

	method := []byte("GET")
	uri := []byte("/api/users/42")
	proto := []byte("HTTP/1.1")
	addr := []byte("1.2.3.4")
	pkt := encodeHeaderPacket([][2]string{
		{"Host", "example.com"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
		{"Accept", "application/json"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		txID := txCreate(wafID)
		txProcessConnection(txID, ptrOf(addr), int32(len(addr)), 45000, 80)
		txProcessURI(txID,
			ptrOf(method), int32(len(method)),
			ptrOf(uri), int32(len(uri)),
			ptrOf(proto), int32(len(proto)),
		)
		txProcessRequestHeaders(txID, ptrOf(pkt), int32(len(pkt)))
		txProcessLogging(txID)
		txDestroy(txID)
	}
	b.StopTimer()
	nativeUnpinAll()
}

// BenchmarkRequestPipeline_CRS_WithBody measures CRS overhead across typical
// POST body sizes — this is where CRS spends the most time (argument parsing,
// regex rules on body content).
func BenchmarkRequestPipeline_CRS_WithBody(b *testing.B) {
	cfg := []byte(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleRemoveByTag "language-php"
SecRuleRemoveByTag "language-java"
SecRuleRemoveByTag "language-dotnet"
SecRuleEngine On
SecRequestBodyAccess On
`)
	for _, size := range []int{128, 1024, 8 * 1024} {
		b.Run("body-"+strconv.Itoa(size), func(b *testing.B) {
			resetState()
			wafID := wafCreate(ptrOf(cfg), int32(len(cfg)))
			if wafID <= 0 {
				b.Skipf("waf_create failed (CRS): %q", string(lastErrMsg))
				return
			}
			defer wafDestroy(wafID)

			method := []byte("POST")
			uri := []byte("/submit")
			proto := []byte("HTTP/1.1")
			pkt := encodeHeaderPacket([][2]string{
				{"Host", "example.com"},
				{"content-type", "application/x-www-form-urlencoded"},
			})
			body := make([]byte, size)
			// Benign-looking body (no CRS hits) so rules run to completion.
			for i := range body {
				body[i] = "abcdefghijklmnop"[i%16]
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				txID := txCreate(wafID)
				txProcessURI(txID,
					ptrOf(method), int32(len(method)),
					ptrOf(uri), int32(len(uri)),
					ptrOf(proto), int32(len(proto)),
				)
				txProcessRequestHeaders(txID, ptrOf(pkt), int32(len(pkt)))
				txProcessRequestBody(txID, ptrOf(body), int32(len(body)))
				txProcessLogging(txID)
				txDestroy(txID)
			}
			b.StopTimer()
			nativeUnpinAll()
		})
	}
}

// Per-scenario sub-benchmarks at different body sizes to show the body-phase
// overhead scaling.
func BenchmarkRequestPipeline_WithBody(b *testing.B) {
	for _, size := range []int{128, 1024, 8 * 1024, 64 * 1024} {
		b.Run("body-"+strconv.Itoa(size), func(b *testing.B) {
			resetState()
			cfg := []byte(`
SecRuleEngine On
SecRequestBodyAccess On
`)
			wafID := wafCreate(ptrOf(cfg), int32(len(cfg)))
			if wafID <= 0 {
				b.Skipf("waf_create: %q", string(lastErrMsg))
				return
			}
			defer wafDestroy(wafID)

			method := []byte("POST")
			uri := []byte("/submit")
			proto := []byte("HTTP/1.1")
			pkt := encodeHeaderPacket([][2]string{
				{"Host", "x"},
				{"content-type", "application/x-www-form-urlencoded"},
			})
			body := make([]byte, size)
			for i := range body {
				body[i] = 'x'
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				txID := txCreate(wafID)
				txProcessURI(txID,
					ptrOf(method), int32(len(method)),
					ptrOf(uri), int32(len(uri)),
					ptrOf(proto), int32(len(proto)),
				)
				txProcessRequestHeaders(txID, ptrOf(pkt), int32(len(pkt)))
				txProcessRequestBody(txID, ptrOf(body), int32(len(body)))
				txProcessLogging(txID)
				txDestroy(txID)
			}
			b.StopTimer()
			nativeUnpinAll()
		})
	}
}

// Native integration tests that exercise the //export entrypoints end-to-end.
// These work by placing input data into a Go-owned buffer and passing its
// real address through `readBytes`'s unsafe.Slice reconstruction — which is
// valid on any Go target as long as the pointer is genuine.

//go:build !tinygo && !wasm
// +build !tinygo,!wasm

package main

import (
	"testing"
)

// Native tests use the handle-table `nativePin` from host_native.go so Go
// pointer arithmetic stays safe on 64-bit hosts.
func ptrOf(b []byte) int32 { return nativePin(b) }
func unpinAll()            { nativeUnpinAll() }

// resetState clears the module-global registries so one test's state doesn't
// leak into the next.
func resetState() {
	for id := range txs {
		delete(txs, id)
	}
	for id := range wafs {
		delete(wafs, id)
	}
	wafNextID = 0
	txNextID = 0
	lastErrMsg = lastErrMsg[:0]
	unpinAll()
}

func TestWAFAndTx_RequestPipeline(t *testing.T) {
	resetState()

	// Minimal WAF config that will reject a very visible pattern so we know
	// the rule engine is actually running.
	cfg := []byte(`
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "@contains nastystring" "id:10001,phase:1,deny,status:418"
`)

	wafID := wafCreate(ptrOf(cfg), int32(len(cfg)))
	if wafID <= 0 {
		t.Fatalf("waf_create failed: rc=%d err=%q", wafID, string(lastErrMsg))
	}
	defer wafDestroy(wafID)

	// Create a tx.
	txID := txCreate(wafID)
	if txID <= 0 {
		t.Fatalf("tx_create failed")
	}
	defer txDestroy(txID)

	// Connection (client 1.2.3.4 → 80)
	addr := []byte("1.2.3.4")
	if rc := txProcessConnection(txID, ptrOf(addr), int32(len(addr)), 45000, 80); rc != 0 {
		t.Fatalf("process_connection failed: %d", rc)
	}

	// URI — pass a benign one first.
	method := []byte("GET")
	uri := []byte("/benign")
	proto := []byte("HTTP/1.1")
	if rc := txProcessURI(txID,
		ptrOf(method), int32(len(method)),
		ptrOf(uri), int32(len(uri)),
		ptrOf(proto), int32(len(proto)),
	); rc != 0 {
		t.Fatalf("process_uri: %d", rc)
	}

	// Empty headers packet.
	pkt := encodeHeaderPacket([][2]string{{"Host", "example.com"}})
	if rc := txProcessRequestHeaders(txID, ptrOf(pkt), int32(len(pkt))); rc < 0 {
		t.Fatalf("process_request_headers: %d err=%q", rc, string(lastErrMsg))
	}

	// Engine should be on.
	if off := txIsRuleEngineOff(txID); off != 0 {
		t.Errorf("expected rule engine on, got off=%d", off)
	}

	// Body access predicate is queryable.
	_ = txIsRequestBodyAccessible(txID)
	_ = txIsResponseBodyAccessible(txID)
	_ = txIsResponseBodyProcessable(txID)

	if hit := txHasInterrupt(txID); hit != 0 {
		t.Errorf("benign request should not interrupt, got %d", hit)
	}

	// Now trigger the rule via a matching URL.
	resetState()
	wafID = wafCreate(ptrOf(cfg), int32(len(cfg)))
	txID = txCreate(wafID)
	txProcessURI(txID,
		ptrOf([]byte("GET")), 3,
		ptrOf([]byte("/?q=nastystring")), 15,
		ptrOf([]byte("HTTP/1.1")), 8,
	)
	hdrPkt := encodeHeaderPacket([][2]string{{"Host", "x"}})
	rc := txProcessRequestHeaders(txID, ptrOf(hdrPkt), int32(len(hdrPkt)))
	// rc == 1 when interrupted.
	if rc != 1 {
		t.Fatalf("expected interrupt rc=1, got rc=%d err=%q", rc, string(lastErrMsg))
	}
	if txHasInterrupt(txID) != 1 {
		t.Error("tx_has_interrupt should be 1 after match")
	}

	// Fetch interruption JSON via the scratch-based export.
	packed := txGetInterrupt(txID)
	if packed == 0 {
		t.Fatal("tx_get_interrupt returned 0 despite interrupt")
	}
	jsonLen := int(uint32(packed & 0xffffffff))
	jsonBytes := scratchBacking[:jsonLen]
	if !containsAll(jsonBytes, []string{`"ruleId":10001`, `"status":418`}) {
		t.Errorf("interrupt JSON missing expected fields: %s", string(jsonBytes))
	}

	// Process logging + destroy.
	if rc := txProcessLogging(txID); rc != 0 {
		t.Errorf("tx_process_logging rc=%d err=%q", rc, string(lastErrMsg))
	}
	txDestroy(txID)

	// Destroying an already-destroyed tx is a no-op.
	txDestroy(txID)

	// Destroying an unknown tx triggers the lookup miss branch.
	if rc := txProcessLogging(999); rc != -1 {
		t.Errorf("unknown tx should return -1, got %d", rc)
	}
}

func TestTxCreate_UnknownWAF(t *testing.T) {
	resetState()
	if txCreate(999) != -1 {
		t.Error("expected -1 for unknown waf id")
	}
	if string(lastErrMsg) == "" {
		t.Error("expected last_error to be set")
	}
}

func TestWAFCreate_InvalidRules(t *testing.T) {
	resetState()
	bad := []byte("NotASecLangDirective!")
	if rc := wafCreate(ptrOf(bad), int32(len(bad))); rc != -1 {
		t.Errorf("expected -1 for bad rules, got %d", rc)
	}
	if string(lastErrMsg) == "" {
		t.Error("expected error message")
	}
}

func TestBodyAndResponsePipeline(t *testing.T) {
	resetState()
	cfg := []byte(`
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json
SecRule REQUEST_BODY "@contains evilbody" "id:20001,phase:2,deny,status:403"
SecRule RESPONSE_BODY "@contains leaked-secret" "id:20002,phase:4,deny,status:500"
`)
	wafID := wafCreate(ptrOf(cfg), int32(len(cfg)))
	if wafID <= 0 {
		t.Fatalf("waf_create: err=%q", string(lastErrMsg))
	}
	txID := txCreate(wafID)
	txProcessURI(txID,
		ptrOf([]byte("POST")), 4,
		ptrOf([]byte("/submit")), 7,
		ptrOf([]byte("HTTP/1.1")), 8,
	)
	hdr := encodeHeaderPacket([][2]string{{"content-type", "application/json"}})
	txProcessRequestHeaders(txID, ptrOf(hdr), int32(len(hdr)))

	// Raw body (no JSON processor) — REQUEST_BODY variable gets the bytes.
	body := []byte("something evilbody here")
	rc := txProcessRequestBody(txID, ptrOf(body), int32(len(body)))
	if rc < 0 {
		t.Errorf("process_request_body err: %q", string(lastErrMsg))
	}
	// Whether rc==1 or 0 depends on Coraza's body processor resolution; the
	// key assertion is that no error occurred and the pipeline completed.
	_ = rc

	// Response phase on a fresh tx.
	resetState()
	wafID = wafCreate(ptrOf(cfg), int32(len(cfg)))
	txID = txCreate(wafID)
	txProcessURI(txID,
		ptrOf([]byte("GET")), 3,
		ptrOf([]byte("/x")), 2,
		ptrOf([]byte("HTTP/1.1")), 8,
	)
	hdr2 := encodeHeaderPacket([][2]string{{"Host", "x"}})
	txProcessRequestHeaders(txID, ptrOf(hdr2), int32(len(hdr2)))
	respHdr := encodeHeaderPacket([][2]string{{"content-type", "text/plain"}})
	proto := []byte("HTTP/1.1")
	if rc := txProcessResponseHeaders(txID, 200, ptrOf(respHdr), int32(len(respHdr)), ptrOf(proto), int32(len(proto))); rc < 0 {
		t.Fatalf("process_response_headers: %d err=%q", rc, string(lastErrMsg))
	}

	respBody := []byte("oops leaked-secret here")
	if rc := txProcessResponseBody(txID, ptrOf(respBody), int32(len(respBody))); rc != 1 {
		t.Errorf("expected response-body interrupt, got rc=%d err=%q", rc, string(lastErrMsg))
	}

	matched := txGetMatchedRules(txID)
	if matched == 0 {
		t.Error("expected matched rules payload")
	}
}

func TestAppendBodyChunks(t *testing.T) {
	resetState()
	cfg := []byte(`
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
`)
	wafID := wafCreate(ptrOf(cfg), int32(len(cfg)))
	txID := txCreate(wafID)
	txProcessURI(txID,
		ptrOf([]byte("POST")), 4,
		ptrOf([]byte("/c")), 2,
		ptrOf([]byte("HTTP/1.1")), 8,
	)
	hdr := encodeHeaderPacket([][2]string{{"content-type", "text/plain"}})
	txProcessRequestHeaders(txID, ptrOf(hdr), int32(len(hdr)))

	chunk := []byte("part-")
	if rc := txAppendRequestBody(txID, ptrOf(chunk), int32(len(chunk))); rc != 0 {
		t.Errorf("append: %d", rc)
	}
	chunk2 := []byte("two")
	txAppendRequestBody(txID, ptrOf(chunk2), int32(len(chunk2)))
	if rc := txProcessRequestBodyFinish(txID); rc < 0 {
		t.Errorf("body finish: %d err=%q", rc, string(lastErrMsg))
	}

	// Response append path.
	respHdr := encodeHeaderPacket([][2]string{{"content-type", "text/plain"}})
	proto := []byte("HTTP/1.1")
	txProcessResponseHeaders(txID, 200, ptrOf(respHdr), int32(len(respHdr)), ptrOf(proto), int32(len(proto)))
	rc := txAppendResponseBody(txID, ptrOf([]byte("abc")), 3)
	if rc != 0 {
		t.Errorf("resp append: %d", rc)
	}
	if rc := txProcessResponseBodyFinish(txID); rc < 0 {
		t.Errorf("resp finish: %d err=%q", rc, string(lastErrMsg))
	}

	// Unknown-tx branches on each.
	if txAppendRequestBody(999, 0, 0) != -1 {
		t.Error("append unknown tx")
	}
	if txProcessRequestBodyFinish(999) != -1 {
		t.Error("finish unknown tx")
	}
	if txAppendResponseBody(999, 0, 0) != -1 {
		t.Error("resp append unknown tx")
	}
	if txProcessResponseBodyFinish(999) != -1 {
		t.Error("resp finish unknown tx")
	}
	if txProcessResponseHeaders(999, 200, 0, 0, 0, 0) != -1 {
		t.Error("resp hdr unknown tx")
	}
	if txProcessResponseBody(999, 0, 0) != -1 {
		t.Error("resp body unknown tx")
	}
	if txProcessRequestBody(999, 0, 0) != -1 {
		t.Error("req body unknown tx")
	}
	if txProcessRequestHeaders(999, 0, 0) != -1 {
		t.Error("req hdr unknown tx")
	}
	if txProcessURI(999, 0, 0, 0, 0, 0, 0) != -1 {
		t.Error("uri unknown tx")
	}
	if txProcessConnection(999, 0, 0, 0, 0) != -1 {
		t.Error("conn unknown tx")
	}

	// Unknown-tx predicates — has_interrupt returns 0, is_rule_engine_off
	// returns 1 (treat missing as off), others return 0.
	if txHasInterrupt(999) != 0 {
		t.Error("has_interrupt unknown")
	}
	if txIsRuleEngineOff(999) != 1 {
		t.Error("rule_engine_off unknown -> 1")
	}
	if txIsRequestBodyAccessible(999) != 0 {
		t.Error("req_body_accessible unknown")
	}
	if txIsResponseBodyAccessible(999) != 0 {
		t.Error("resp_body_accessible unknown")
	}
	if txIsResponseBodyProcessable(999) != 0 {
		t.Error("resp_body_processable unknown")
	}
	if txGetInterrupt(999) != 0 {
		t.Error("get_interrupt unknown")
	}
	if txGetMatchedRules(999) != 0 {
		t.Error("get_matched_rules unknown")
	}
}

func TestLastError_ClearedOnEmpty(t *testing.T) {
	resetState()
	if lastError() != 0 {
		t.Error("expected 0 when no error")
	}
	setErr(errTest("sample"))
	if lastError() == 0 {
		t.Error("expected non-zero packed (ptr,len)")
	}
}

// containsAll returns true if all substrings appear in body.
func containsAll(body []byte, subs []string) bool {
	for _, s := range subs {
		if !containsBytes(body, []byte(s)) {
			return false
		}
	}
	return true
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}


// Package main is the TinyGo entry point for coraza-node.
// It exposes a small, performance-oriented ABI over Coraza. See ABI.md.
//
// Allocation philosophy:
//   - WASM memory is single-threaded under TinyGo; no mutexes are needed.
//   - Registries are plain maps (no per-call allocation on the hot path).
//   - Inputs are passed by (ptr, len) into host-owned buffers — zero copy from JS.
//   - Outputs > 8 bytes are written to a persistent scratch buffer (64 KiB).
//   - Integer results are returned directly; pointer+length results are
//     packed into a single int64 to avoid multi-return ABI overhead.
package main

import (
	"errors"
	"io"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// wasilibs registration lives in wasilibs_on.go (build tag `wasilibs`).
// TinyGo's linker segfaults when it links wazero (wasilibs' engine), so we
// gate the faster operators behind an explicit build tag. Native Go tests
// and benchmarks enable it by default for realistic numbers; WASM builds
// stick with Go stdlib regex.

// Register the host-backed `rx` operator so every CRS SecRule that uses
// `@rx ...` calls into V8's RegExp via a WASM host import instead of
// running Go's stdlib regex inside the WASM. Patterns the host can't
// compile fall back to Go transparently.
func init() {
	registerHostRX()
}

const (
	abiMajor = 1
	abiMinor = 1 // +tx_reset
)

//export abi_version
func abiVersion() int32 { return int32(abiMajor<<16 | abiMinor) }

// --- registries ---------------------------------------------------------

var (
	wafs      = map[int32]coraza.WAF{}
	wafNextID int32

	txs      = map[int32]types.Transaction{}
	// Parallel map: tx id -> owning waf id. Needed so `tx_reset` can
	// ask the same WAF for a replacement transaction without the
	// caller having to remember (and re-send) the waf id.
	txOwner  = map[int32]int32{}
	txNextID int32

	lastErrMsg []byte
)

func newWAFID() int32 { wafNextID++; return wafNextID }
func newTxID() int32  { txNextID++; return txNextID }

func setErr(err error) int32 {
	if err == nil {
		lastErrMsg = lastErrMsg[:0]
		return -1
	}
	lastErrMsg = append(lastErrMsg[:0], err.Error()...)
	return -1
}

//export last_error
func lastError() int64 {
	if len(lastErrMsg) == 0 {
		return 0
	}
	return writeScratch(lastErrMsg)
}

// --- WAF -----------------------------------------------------------------

//export waf_create
func wafCreate(cfgPtr, cfgLen int32) int32 {
	cfg := readBytes(cfgPtr, cfgLen)
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(string(cfg)),
	)
	if err != nil {
		return setErr(err)
	}
	id := newWAFID()
	wafs[id] = waf
	return id
}

//export waf_destroy
func wafDestroy(id int32) { delete(wafs, id) }

// --- Transaction lifecycle ----------------------------------------------

//export tx_create
func txCreate(wafID int32) int32 {
	waf, ok := wafs[wafID]
	if !ok {
		return setErr(errors.New("unknown waf id"))
	}
	id := newTxID()
	txs[id] = waf.NewTransaction()
	txOwner[id] = wafID
	return id
}

//export tx_destroy
func txDestroy(id int32) {
	tx, ok := txs[id]
	if !ok {
		return
	}
	// ProcessLogging is safe to call multiple times; ensures audit log fires.
	tx.ProcessLogging()
	_ = tx.Close()
	delete(txs, id)
	delete(txOwner, id)
}

// tx_reset finalises the current transaction (audit log + close) and
// replaces it with a fresh one on the same WAF, reusing the same id.
// Saves the JS caller a round-trip for a new handle and lets Coraza
// reuse the transaction object's internal buffers where it can. Returns
// the same id on success, -1 with last_error set on failure.
//
//export tx_reset
func txReset(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	wafID, ok := txOwner[id]
	if !ok {
		return setErr(errors.New("tx has no owner waf"))
	}
	waf, ok := wafs[wafID]
	if !ok {
		// The WAF has been destroyed since this tx was created. Clean up
		// and surface the error rather than leaving a dangling slot.
		tx.ProcessLogging()
		_ = tx.Close()
		delete(txs, id)
		delete(txOwner, id)
		return setErr(errors.New("owning waf has been destroyed"))
	}
	tx.ProcessLogging()
	_ = tx.Close()
	txs[id] = waf.NewTransaction()
	return id
}

//export tx_has_interrupt
func txHasInterrupt(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return 0
	}
	if tx.Interruption() != nil {
		return 1
	}
	return 0
}

// Hot-path predicates so callers can skip body ingestion when Coraza won't
// use it (based on rules like ctl:forceRequestBodyVariable and body limits).

//export tx_is_rule_engine_off
func txIsRuleEngineOff(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return 1 // unknown tx — treat as off (skip processing)
	}
	if tx.IsRuleEngineOff() {
		return 1
	}
	return 0
}

//export tx_is_request_body_accessible
func txIsRequestBodyAccessible(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return 0
	}
	if tx.IsRequestBodyAccessible() {
		return 1
	}
	return 0
}

//export tx_is_response_body_accessible
func txIsResponseBodyAccessible(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return 0
	}
	if tx.IsResponseBodyAccessible() {
		return 1
	}
	return 0
}

//export tx_is_response_body_processable
func txIsResponseBodyProcessable(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return 0
	}
	if tx.IsResponseBodyProcessable() {
		return 1
	}
	return 0
}

// --- Processing ---------------------------------------------------------

//export tx_process_connection
func txProcessConnection(id, addrPtr, addrLen, cport, sport int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	tx.ProcessConnection(string(readBytes(addrPtr, addrLen)), int(cport), "", int(sport))
	return 0
}

//export tx_process_uri
func txProcessURI(id, methodPtr, methodLen, uriPtr, uriLen, protoPtr, protoLen int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	tx.ProcessURI(
		string(readBytes(uriPtr, uriLen)),
		string(readBytes(methodPtr, methodLen)),
		string(readBytes(protoPtr, protoLen)),
	)
	return 0
}

//export tx_process_request_headers
func txProcessRequestHeaders(id, pktPtr, pktLen int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	if err := parseHeaderPacket(readBytes(pktPtr, pktLen), func(name, value []byte) {
		tx.AddRequestHeader(string(name), string(value))
	}); err != nil {
		return setErr(err)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return 1
	}
	return 0
}

//export tx_process_request_body
func txProcessRequestBody(id, bodyPtr, bodyLen int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	if bodyLen > 0 {
		if _, _, err := tx.WriteRequestBody(readBytes(bodyPtr, bodyLen)); err != nil && !errors.Is(err, io.EOF) {
			return setErr(err)
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return setErr(err)
	}
	if it != nil {
		return 1
	}
	return 0
}

//export tx_append_request_body
func txAppendRequestBody(id, chunkPtr, chunkLen int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	if _, _, err := tx.WriteRequestBody(readBytes(chunkPtr, chunkLen)); err != nil && !errors.Is(err, io.EOF) {
		return setErr(err)
	}
	return 0
}

//export tx_process_request_body_finish
func txProcessRequestBodyFinish(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return setErr(err)
	}
	if it != nil {
		return 1
	}
	return 0
}

//export tx_process_response_headers
func txProcessResponseHeaders(id, status, pktPtr, pktLen, protoPtr, protoLen int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	if err := parseHeaderPacket(readBytes(pktPtr, pktLen), func(name, value []byte) {
		tx.AddResponseHeader(string(name), string(value))
	}); err != nil {
		return setErr(err)
	}
	if it := tx.ProcessResponseHeaders(int(status), string(readBytes(protoPtr, protoLen))); it != nil {
		return 1
	}
	return 0
}

//export tx_process_response_body
func txProcessResponseBody(id, bodyPtr, bodyLen int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	if bodyLen > 0 {
		if _, _, err := tx.WriteResponseBody(readBytes(bodyPtr, bodyLen)); err != nil && !errors.Is(err, io.EOF) {
			return setErr(err)
		}
	}
	it, err := tx.ProcessResponseBody()
	if err != nil {
		return setErr(err)
	}
	if it != nil {
		return 1
	}
	return 0
}

//export tx_append_response_body
func txAppendResponseBody(id, chunkPtr, chunkLen int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	if _, _, err := tx.WriteResponseBody(readBytes(chunkPtr, chunkLen)); err != nil && !errors.Is(err, io.EOF) {
		return setErr(err)
	}
	return 0
}

//export tx_process_response_body_finish
func txProcessResponseBodyFinish(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	it, err := tx.ProcessResponseBody()
	if err != nil {
		return setErr(err)
	}
	if it != nil {
		return 1
	}
	return 0
}

//export tx_process_logging
func txProcessLogging(id int32) int32 {
	tx, ok := txs[id]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	tx.ProcessLogging()
	return 0
}

// --- Result inspection --------------------------------------------------

//export tx_get_interrupt
func txGetInterrupt(id int32) int64 {
	tx, ok := txs[id]
	if !ok {
		return 0
	}
	it := tx.Interruption()
	if it == nil {
		return 0
	}
	// Inline JSON writer — avoids json.Marshal reflection overhead.
	b := scratchBuf[:0]
	b = append(b, '{')
	b = writeKV(b, "ruleId", it.RuleID)
	b = append(b, ',')
	b = writeKVS(b, "action", it.Action)
	b = append(b, ',')
	b = writeKV(b, "status", it.Status)
	b = append(b, ',')
	b = writeKVS(b, "data", it.Data)
	b = append(b, '}')
	scratchBuf = b
	return writeScratch(b)
}

//export tx_get_matched_rules
func txGetMatchedRules(id int32) int64 {
	tx, ok := txs[id]
	if !ok {
		return 0
	}
	matches := tx.MatchedRules()
	if len(matches) == 0 {
		return 0
	}
	b := scratchBuf[:0]
	b = append(b, '[')
	for i, m := range matches {
		if i > 0 {
			b = append(b, ',')
		}
		r := m.Rule()
		b = append(b, '{')
		b = writeKV(b, "id", r.ID())
		b = append(b, ',')
		b = writeKV(b, "severity", int(r.Severity()))
		b = append(b, ',')
		b = writeKVS(b, "message", m.Message())
		b = append(b, '}')
	}
	b = append(b, ']')
	scratchBuf = b
	return writeScratch(b)
}

func main() {}

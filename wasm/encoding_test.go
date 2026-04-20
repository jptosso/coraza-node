package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseHeaderPacket_Empty(t *testing.T) {
	pkt := make([]byte, 4) // count=0
	count := 0
	if err := parseHeaderPacket(pkt, func(_, _ []byte) { count++ }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 callbacks, got %d", count)
	}
}

func TestParseHeaderPacket_RoundTrip(t *testing.T) {
	headers := [][2]string{
		{"Host", "example.com"},
		{"Content-Type", "application/json"},
		{"X-Empty", ""},
	}
	pkt := encodeHeaderPacket(headers)

	var got [][2]string
	err := parseHeaderPacket(pkt, func(name, value []byte) {
		got = append(got, [2]string{string(name), string(value)})
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != len(headers) {
		t.Fatalf("want %d headers, got %d", len(headers), len(got))
	}
	for i := range headers {
		if got[i] != headers[i] {
			t.Errorf("header %d: want %v, got %v", i, headers[i], got[i])
		}
	}
}

func TestParseHeaderPacket_TooShort(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3} {
		pkt := make([]byte, size)
		if err := parseHeaderPacket(pkt, func(_, _ []byte) {}); err == nil {
			t.Errorf("size %d: expected error", size)
		}
	}
}

func TestParseHeaderPacket_Truncated(t *testing.T) {
	// Valid packet with one header, then truncate at each boundary.
	pkt := encodeHeaderPacket([][2]string{{"X", "Y"}})
	for i := 5; i < len(pkt); i++ {
		if err := parseHeaderPacket(pkt[:i], func(_, _ []byte) {}); err == nil {
			t.Errorf("truncated at %d: expected error", i)
		}
	}
}

func TestParseHeaderPacket_CorruptedLengths(t *testing.T) {
	// count=1, name_len oversized
	pkt := make([]byte, 4+4)
	binary.LittleEndian.PutUint32(pkt[0:4], 1)
	binary.LittleEndian.PutUint32(pkt[4:8], 99) // claims 99 bytes of name but packet ends
	if err := parseHeaderPacket(pkt, func(_, _ []byte) {}); err == nil {
		t.Error("expected truncated-name error")
	}

	// count=1, name ok, value_len oversized
	pkt = append(pkt[:0], encodeHeaderPacket([][2]string{{"A", "B"}})...)
	// Overwrite value_len to huge.
	binary.LittleEndian.PutUint32(pkt[4+4+1:4+4+1+4], 99)
	if err := parseHeaderPacket(pkt, func(_, _ []byte) {}); err == nil {
		t.Error("expected truncated-value error")
	}
}

func TestParseHeaderPacket_MissingNameLenMidStream(t *testing.T) {
	// count=2, one header, truncate before name_len of second.
	pkt := encodeHeaderPacket([][2]string{{"A", "B"}})
	binary.LittleEndian.PutUint32(pkt[0:4], 2) // claim 2 but only one serialized
	if err := parseHeaderPacket(pkt, func(_, _ []byte) {}); err == nil {
		t.Error("expected truncated-name_len error on second header")
	}
}

func TestParseHeaderPacket_MissingValueLenMidStream(t *testing.T) {
	// count=1, name present but value_len byte missing.
	pkt := make([]byte, 4+4+3)              // count + name_len(4) + name(3) + nothing
	binary.LittleEndian.PutUint32(pkt[0:4], 1)
	binary.LittleEndian.PutUint32(pkt[4:8], 3)
	copy(pkt[8:], "abc")
	if err := parseHeaderPacket(pkt, func(_, _ []byte) {}); err == nil {
		t.Error("expected truncated-value_len error")
	}
}

func TestEncodeHeaderPacket_LayoutMatchesSpec(t *testing.T) {
	pkt := encodeHeaderPacket([][2]string{{"Host", "localhost"}})
	if got := binary.LittleEndian.Uint32(pkt[0:4]); got != 1 {
		t.Fatalf("count: got %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(pkt[4:8]); got != 4 {
		t.Fatalf("name_len: got %d, want 4", got)
	}
	if string(pkt[8:12]) != "Host" {
		t.Fatalf("name: got %q, want Host", string(pkt[8:12]))
	}
}

func TestWriteInt(t *testing.T) {
	cases := map[int64]string{
		0:                   "0",
		1:                   "1",
		42:                  "42",
		-1:                  "-1",
		-12345:              "-12345",
		9223372036854775807: "9223372036854775807",
	}
	for in, want := range cases {
		if got := string(writeInt(nil, in)); got != want {
			t.Errorf("writeInt(%d): got %q, want %q", in, got, want)
		}
	}
}

func TestWriteKV(t *testing.T) {
	got := string(writeKV(nil, "x", 7))
	if got != `"x":7` {
		t.Errorf(`got %q, want "x":7`, got)
	}
}

func TestWriteKVS_BasicAndEscapes(t *testing.T) {
	// Plain
	got := string(writeKVS(nil, "msg", "hi"))
	if got != `"msg":"hi"` {
		t.Errorf("plain: got %q", got)
	}

	// All escape sequences
	got = string(writeKVS(nil, "k", "\"\\\n\r\t"))
	want := `"k":"\"\\\n\r\t"`
	if got != want {
		t.Errorf("escapes: got %q, want %q", got, want)
	}

	// Control character (below 0x20 but not in the fast-path set) gets \u00XX
	got = string(writeKVS(nil, "k", "\x01"))
	if !strings.Contains(got, `\u0001`) {
		t.Errorf("expected \\u0001 escape, got %q", got)
	}

	// Printable unicode stays as-is (UTF-8 byte-preserving — we escape only
	// ASCII controls, anything >= 0x20 is passed through).
	got = string(writeKVS(nil, "k", "héllo"))
	if !strings.Contains(got, "hello") && !strings.Contains(got, "héllo") {
		t.Errorf("unicode lost: %q", got)
	}
}

func TestHexDigit(t *testing.T) {
	table := map[byte]byte{
		0:  '0',
		9:  '9',
		10: 'a',
		15: 'f',
	}
	for in, want := range table {
		if got := hexDigit(in); got != want {
			t.Errorf("hexDigit(%d): got %q, want %q", in, got, want)
		}
	}
}

// ------------- registry + last_error tests (pure-Go, no WASM) -------------

func TestSetErr_StoresAndClears(t *testing.T) {
	// Clear state
	lastErrMsg = lastErrMsg[:0]

	if got := setErr(nil); got != -1 {
		t.Errorf("setErr(nil): got %d, want -1", got)
	}
	if len(lastErrMsg) != 0 {
		t.Errorf("setErr(nil) should clear: got %q", lastErrMsg)
	}

	setErr(errTest("boom"))
	if string(lastErrMsg) != "boom" {
		t.Errorf("after setErr: got %q", lastErrMsg)
	}

	// Overwrite
	setErr(errTest("newer"))
	if string(lastErrMsg) != "newer" {
		t.Errorf("overwrite: got %q", lastErrMsg)
	}

	// Cleanup for other tests
	lastErrMsg = lastErrMsg[:0]
}

func TestIDAllocators(t *testing.T) {
	wafNextID = 0
	txNextID = 0
	a := newWAFID()
	b := newWAFID()
	if a == b || b != a+1 {
		t.Errorf("waf IDs not monotonic: %d, %d", a, b)
	}
	c := newTxID()
	d := newTxID()
	if c == d || d != c+1 {
		t.Errorf("tx IDs not monotonic: %d, %d", c, d)
	}
}

// errTest is a tiny helper error type — avoids importing fmt.Errorf for
// trivial test strings.
type errTest string

func (e errTest) Error() string { return string(e) }

func TestAbiVersion(t *testing.T) {
	v := abiVersion()
	major := (v >> 16) & 0xffff
	if major != abiMajor {
		t.Errorf("abi_version major: got %d, want %d", major, abiMajor)
	}
}

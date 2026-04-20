//go:build tinygo || wasm
// +build tinygo wasm

// Bundle the full request (connection + URI + headers + body) into one
// WASM call. Saves ~10 boundary crossings per request vs individual
// process_connection + process_uri + process_request_headers +
// process_request_body — the win shows up mostly in pool mode where
// every crossing is a MessagePort round-trip.
//
// Bundle wire format (all integers little-endian):
//
//   [addr_len:   u16]  [addr bytes]
//   [cport:      u16]
//   [sport:      u16]
//   [method_len: u8]   [method bytes]
//   [proto_len:  u8]   [proto bytes]
//   [url_len:    u32]  [url bytes]
//   [hdr_len:    u32]  [header packet — see ABI.md]
//   [body_len:   u32]  [body bytes]
//
// Layout is tight: no alignment padding. Fields appear in the natural
// order the host builds them. Oversizing a single packet beyond the
// scratch budget is fine — the host uses host_malloc for the bundle.

package main

import (
	"encoding/binary"
	"errors"
	"io"
)

//export tx_process_request_bundle
func txProcessRequestBundle(txID, bundlePtr, bundleLen int32) int32 {
	tx, ok := txs[txID]
	if !ok {
		return setErr(errors.New("unknown tx id"))
	}
	pkt := readBytes(bundlePtr, bundleLen)

	off := 0
	readU16 := func() (uint16, bool) {
		if off+2 > len(pkt) {
			return 0, false
		}
		v := binary.LittleEndian.Uint16(pkt[off : off+2])
		off += 2
		return v, true
	}
	readU32 := func() (uint32, bool) {
		if off+4 > len(pkt) {
			return 0, false
		}
		v := binary.LittleEndian.Uint32(pkt[off : off+4])
		off += 4
		return v, true
	}
	readU8 := func() (uint8, bool) {
		if off+1 > len(pkt) {
			return 0, false
		}
		v := pkt[off]
		off++
		return v, true
	}
	readBlob := func(n int) ([]byte, bool) {
		if off+n > len(pkt) {
			return nil, false
		}
		b := pkt[off : off+n]
		off += n
		return b, true
	}

	// Decode.
	addrLen, ok1 := readU16()
	addr, ok2 := readBlob(int(addrLen))
	cport, ok3 := readU16()
	sport, ok4 := readU16()
	methodLen, ok5 := readU8()
	method, ok6 := readBlob(int(methodLen))
	protoLen, ok7 := readU8()
	proto, ok8 := readBlob(int(protoLen))
	urlLen, ok9 := readU32()
	url, ok10 := readBlob(int(urlLen))
	hdrLen, ok11 := readU32()
	hdr, ok12 := readBlob(int(hdrLen))
	bodyLen, ok13 := readU32()
	body, ok14 := readBlob(int(bodyLen))

	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8 && ok9 && ok10 && ok11 && ok12 && ok13 && ok14) {
		return setErr(errors.New("malformed bundle"))
	}

	// Run phases 1 + 2 in order.
	tx.ProcessConnection(string(addr), int(cport), "", int(sport))
	tx.ProcessURI(string(url), string(method), string(proto))
	if err := parseHeaderPacket(hdr, func(name, value []byte) {
		tx.AddRequestHeader(string(name), string(value))
	}); err != nil {
		return setErr(err)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return 1
	}
	if len(body) > 0 {
		if _, _, err := tx.WriteRequestBody(body); err != nil && !errors.Is(err, io.EOF) {
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

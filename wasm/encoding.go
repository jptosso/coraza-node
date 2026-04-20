// Pure-Go (no unsafe, no WASM-specific imports) helpers extracted so they
// can be covered by native `go test`. main.go keeps the //export shims;
// all non-trivial logic lives here.

package main

import (
	"encoding/binary"
	"errors"
)

// parseHeaderPacket walks the compact binary header packet described in ABI.md.
//
//	[count: u32][name_len: u32][name][value_len: u32][value]...
//
// Allocates no per-entry intermediate — the callback receives slices
// aliasing the input.
func parseHeaderPacket(pkt []byte, cb func(name, value []byte)) error {
	if len(pkt) < 4 {
		return errors.New("header packet too short")
	}
	count := binary.LittleEndian.Uint32(pkt[0:4])
	i := uint32(4)
	for k := uint32(0); k < count; k++ {
		if i+4 > uint32(len(pkt)) {
			return errors.New("header packet truncated (name_len)")
		}
		nl := binary.LittleEndian.Uint32(pkt[i : i+4])
		i += 4
		if i+nl > uint32(len(pkt)) {
			return errors.New("header packet truncated (name)")
		}
		name := pkt[i : i+nl]
		i += nl
		if i+4 > uint32(len(pkt)) {
			return errors.New("header packet truncated (value_len)")
		}
		vl := binary.LittleEndian.Uint32(pkt[i : i+4])
		i += 4
		if i+vl > uint32(len(pkt)) {
			return errors.New("header packet truncated (value)")
		}
		cb(name, pkt[i:i+vl])
		i += vl
	}
	return nil
}

// encodeHeaderPacket is the Go-side inverse of parseHeaderPacket (used only
// by tests to round-trip). Not exposed on the ABI.
func encodeHeaderPacket(headers [][2]string) []byte {
	size := 4
	for _, h := range headers {
		size += 4 + len(h[0]) + 4 + len(h[1])
	}
	out := make([]byte, size)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(headers)))
	off := uint32(4)
	for _, h := range headers {
		binary.LittleEndian.PutUint32(out[off:], uint32(len(h[0])))
		off += 4
		copy(out[off:], h[0])
		off += uint32(len(h[0]))
		binary.LittleEndian.PutUint32(out[off:], uint32(len(h[1])))
		off += 4
		copy(out[off:], h[1])
		off += uint32(len(h[1]))
	}
	return out
}

// --- tiny JSON writer ---

func writeKV(b []byte, key string, val int) []byte {
	b = append(b, '"')
	b = append(b, key...)
	b = append(b, '"', ':')
	b = writeInt(b, int64(val))
	return b
}

func writeKVS(b []byte, key, val string) []byte {
	b = append(b, '"')
	b = append(b, key...)
	b = append(b, '"', ':', '"')
	for _, r := range []byte(val) {
		switch r {
		case '"', '\\':
			b = append(b, '\\', r)
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if r < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hexDigit(r>>4), hexDigit(r&0xf))
			} else {
				b = append(b, r)
			}
		}
	}
	b = append(b, '"')
	return b
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

func writeInt(b []byte, n int64) []byte {
	if n == 0 {
		return append(b, '0')
	}
	if n < 0 {
		b = append(b, '-')
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return append(b, buf[i:]...)
}

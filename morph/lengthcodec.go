// Package morph implements the polymorphic wire format layer.
package morph

import (
	"encoding/binary"
	"fmt"
)

// LengthEncoding identifies how payload length is serialized on the wire.
type LengthEncoding int

const (
	LenUint16BE  LengthEncoding = iota // big-endian uint16
	LenUint16LE                        // little-endian uint16
	LenVarint                          // unsigned varint (1-3 bytes)
	LenXORUint16                       // big-endian uint16 XOR'd with a mask
)

// LengthCodec encodes and decodes a uint16 length field.
type LengthCodec interface {
	// Encode writes the length to buf and returns bytes written.
	Encode(length uint16, buf []byte) int
	// Decode reads a length from buf and returns (value, bytes consumed).
	Decode(buf []byte) (uint16, int, error)
	// MaxSize returns the maximum encoded size.
	MaxSize() int
	// FixedSize returns true if encoding always uses the same number of bytes.
	FixedSize() bool
}

func NewLengthCodec(enc LengthEncoding, xorMask uint16) LengthCodec {
	switch enc {
	case LenUint16BE:
		return beCodec{}
	case LenUint16LE:
		return leCodec{}
	case LenVarint:
		return varintCodec{}
	case LenXORUint16:
		return xorCodec{mask: xorMask}
	default:
		panic(fmt.Sprintf("morph: unknown LengthEncoding %d", enc))
	}
}

// --- big-endian uint16 ---

type beCodec struct{}

func (beCodec) Encode(v uint16, buf []byte) int {
	binary.BigEndian.PutUint16(buf, v)
	return 2
}

func (beCodec) Decode(buf []byte) (uint16, int, error) {
	if len(buf) < 2 {
		return 0, 0, fmt.Errorf("morph: BE decode: need 2 bytes, have %d", len(buf))
	}
	return binary.BigEndian.Uint16(buf), 2, nil
}

func (beCodec) MaxSize() int    { return 2 }
func (beCodec) FixedSize() bool { return true }

// --- little-endian uint16 ---

type leCodec struct{}

func (leCodec) Encode(v uint16, buf []byte) int {
	binary.LittleEndian.PutUint16(buf, v)
	return 2
}

func (leCodec) Decode(buf []byte) (uint16, int, error) {
	if len(buf) < 2 {
		return 0, 0, fmt.Errorf("morph: LE decode: need 2 bytes, have %d", len(buf))
	}
	return binary.LittleEndian.Uint16(buf), 2, nil
}

func (leCodec) MaxSize() int    { return 2 }
func (leCodec) FixedSize() bool { return true }

// --- unsigned varint ---

type varintCodec struct{}

func (varintCodec) Encode(v uint16, buf []byte) int {
	return binary.PutUvarint(buf, uint64(v))
}

func (varintCodec) Decode(buf []byte) (uint16, int, error) {
	val, n := binary.Uvarint(buf)
	if n <= 0 {
		return 0, 0, fmt.Errorf("morph: varint decode: invalid or insufficient data")
	}
	if val > 0xFFFF {
		return 0, 0, fmt.Errorf("morph: varint value %d overflows uint16", val)
	}
	return uint16(val), n, nil
}

func (varintCodec) MaxSize() int    { return 3 }
func (varintCodec) FixedSize() bool { return false }

// --- XOR-masked big-endian uint16 ---

type xorCodec struct {
	mask uint16
}

func (c xorCodec) Encode(v uint16, buf []byte) int {
	binary.BigEndian.PutUint16(buf, v^c.mask)
	return 2
}

func (c xorCodec) Decode(buf []byte) (uint16, int, error) {
	if len(buf) < 2 {
		return 0, 0, fmt.Errorf("morph: XOR decode: need 2 bytes, have %d", len(buf))
	}
	return binary.BigEndian.Uint16(buf) ^ c.mask, 2, nil
}

func (xorCodec) MaxSize() int    { return 2 }
func (xorCodec) FixedSize() bool { return true }

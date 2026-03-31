package morph

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Frame represents one wire packet's components before/after encoding.
type Frame struct {
	Nonce      []byte // AEAD nonce
	Epoch      uint32 // anti-replay counter
	Ciphertext []byte // AEAD-encrypted payload (without tag)
	Tag        []byte // AEAD authentication tag (16 bytes)
	Padding    []byte // random padding
}

// Encoder writes frames to wire format according to a genome.
type Encoder struct {
	genome *Genome
	codec  LengthCodec
}

// NewEncoder creates a frame encoder for the given genome.
func NewEncoder(g *Genome) *Encoder {
	return &Encoder{
		genome: g,
		codec:  NewLengthCodec(g.LengthEnc, g.LengthXORMask),
	}
}

// Encode serializes a Frame into wire bytes according to the genome.
// The ciphertext field should be the AEAD Seal output WITHOUT the tag,
// and Tag should be the 16-byte authentication tag.
func (e *Encoder) Encode(f *Frame) ([]byte, error) {
	padLen := len(f.Padding)
	if padLen > 255 {
		return nil, fmt.Errorf("morph: padding length %d exceeds 1-byte max", padLen)
	}

	payloadLen := len(f.Ciphertext)
	if payloadLen > 0xFFFF {
		return nil, fmt.Errorf("morph: ciphertext length %d exceeds uint16 max", payloadLen)
	}

	// Calculate total size.
	totalSize := 1 // magic byte
	for _, field := range e.genome.Fields {
		if field.Size > 0 {
			totalSize += field.Size
		} else {
			// Variable-length: encode to temp to know size.
			var tmp [3]byte
			totalSize += e.codec.Encode(uint16(payloadLen), tmp[:])
		}
	}
	totalSize += payloadLen + padLen

	buf := make([]byte, totalSize)
	pos := 0

	// Magic byte.
	buf[pos] = e.genome.MagicByte
	pos++

	// Write fields in genome order.
	for _, field := range e.genome.Fields {
		switch field.ID {
		case FieldNonce:
			copy(buf[pos:], f.Nonce)
			pos += field.Size

		case FieldLength:
			if field.Size > 0 {
				pos += e.codec.Encode(uint16(payloadLen), buf[pos:])
			} else {
				pos += e.codec.Encode(uint16(payloadLen), buf[pos:])
			}

		case FieldPadLen:
			buf[pos] = byte(padLen)
			pos++

		case FieldTag:
			copy(buf[pos:], f.Tag)
			pos += field.Size

		case FieldEpoch:
			binary.BigEndian.PutUint32(buf[pos:], f.Epoch)
			pos += 4

		case FieldDecoy:
			// Fill decoy with random bytes XOR'd with mask.
			decoyBytes := make([]byte, field.Size)
			rand.Read(decoyBytes)
			for i := 0; i < field.Size; i++ {
				if i < len(field.XORMask) {
					buf[pos+i] = decoyBytes[i] ^ field.XORMask[i]
				} else {
					buf[pos+i] = decoyBytes[i]
				}
			}
			pos += field.Size
		}
	}

	// Ciphertext.
	copy(buf[pos:], f.Ciphertext)
	pos += payloadLen

	// Padding.
	if padLen > 0 {
		copy(buf[pos:], f.Padding)
	}

	return buf, nil
}

// Decoder reads frames from wire bytes according to a genome.
type Decoder struct {
	genome *Genome
	codec  LengthCodec
}

// NewDecoder creates a frame decoder for the given genome.
func NewDecoder(g *Genome) *Decoder {
	return &Decoder{
		genome: g,
		codec:  NewLengthCodec(g.LengthEnc, g.LengthXORMask),
	}
}

// Decode parses raw wire bytes into a Frame according to the genome.
func (d *Decoder) Decode(raw []byte) (*Frame, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("morph: packet too short")
	}

	// Check magic byte.
	if raw[0] != d.genome.MagicByte {
		return nil, fmt.Errorf("morph: magic byte mismatch: got 0x%02x, want 0x%02x", raw[0], d.genome.MagicByte)
	}

	pos := 1
	f := &Frame{}
	var payloadLen uint16
	var padLen byte

	// Read fields in genome order.
	for _, field := range d.genome.Fields {
		switch field.ID {
		case FieldNonce:
			if pos+field.Size > len(raw) {
				return nil, fmt.Errorf("morph: truncated at nonce field (pos=%d, need=%d, have=%d)", pos, field.Size, len(raw)-pos)
			}
			f.Nonce = make([]byte, field.Size)
			copy(f.Nonce, raw[pos:pos+field.Size])
			pos += field.Size

		case FieldLength:
			remaining := raw[pos:]
			val, n, err := d.codec.Decode(remaining)
			if err != nil {
				return nil, fmt.Errorf("morph: decoding length: %w", err)
			}
			payloadLen = val
			pos += n

		case FieldPadLen:
			if pos >= len(raw) {
				return nil, fmt.Errorf("morph: truncated at padlen field")
			}
			padLen = raw[pos]
			pos++

		case FieldTag:
			if pos+field.Size > len(raw) {
				return nil, fmt.Errorf("morph: truncated at tag field")
			}
			f.Tag = make([]byte, field.Size)
			copy(f.Tag, raw[pos:pos+field.Size])
			pos += field.Size

		case FieldEpoch:
			if pos+4 > len(raw) {
				return nil, fmt.Errorf("morph: truncated at epoch field")
			}
			f.Epoch = binary.BigEndian.Uint32(raw[pos:])
			pos += 4

		case FieldDecoy:
			if pos+field.Size > len(raw) {
				return nil, fmt.Errorf("morph: truncated at decoy field")
			}
			pos += field.Size // skip decoy bytes
		}
	}

	// Ciphertext.
	if pos+int(payloadLen) > len(raw) {
		return nil, fmt.Errorf("morph: truncated ciphertext: need %d bytes at pos %d, have %d", payloadLen, pos, len(raw))
	}
	f.Ciphertext = make([]byte, payloadLen)
	copy(f.Ciphertext, raw[pos:pos+int(payloadLen)])
	pos += int(payloadLen)

	// Padding.
	if padLen > 0 {
		if pos+int(padLen) > len(raw) {
			return nil, fmt.Errorf("morph: truncated padding")
		}
		f.Padding = make([]byte, padLen)
		copy(f.Padding, raw[pos:pos+int(padLen)])
	}

	return f, nil
}

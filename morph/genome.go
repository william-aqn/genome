package morph

import (
	"fmt"

	"genome/internal/randutil"
)

// FieldID identifies a header field type.
type FieldID int

const (
	FieldNonce  FieldID = iota // AEAD nonce
	FieldLength                // payload length
	FieldPadLen                // padding length
	FieldTag                   // AEAD authentication tag
	FieldEpoch                 // anti-replay counter
	FieldDecoy                 // decoy (random filler)
)

// FieldSpec describes one header field.
type FieldSpec struct {
	ID      FieldID
	Size    int    // fixed size in bytes; 0 = variable (varint only, for FieldLength)
	Decoy   bool   // true if this field is random filler
	XORMask []byte // XOR mask for decoy fields (genome-derived)
}

// Genome is the complete wire format description for a session.
// Deterministically derived from a seed. Both peers with the same
// seed produce identical Genomes.
type Genome struct {
	MagicByte     byte
	Fields        []FieldSpec
	NonceSize     int            // 12 or 24 bytes
	LengthEnc     LengthEncoding // how payload length is encoded
	LengthXORMask uint16         // used only when LengthEnc == LenXORUint16
	PadMin        int            // minimum padding bytes
	PadMax        int            // maximum padding bytes
	TagSize       int            // always 16 (Poly1305/GCM)
	EpochSize     int            // always 4 (uint32)

	// Stream-mode wagon size range (plaintext size inside AEAD).
	// Each tick the pump draws a fresh wagon size from [WagonMin, WagonMax].
	// Always derived (even when stream mode is off at runtime) so both
	// endpoints know the envelope when/if they enable it.
	// Invariant: WagonMin >= muxMSS + 2 so any MSS-sized mux command fits
	// inside the shortest wagon with a 2-byte length prefix.
	WagonMin int
	WagonMax int
}

// Derive deterministically generates a Genome from a seed.
// Same seed always produces identical Genome on any platform.
func Derive(seed []byte) *Genome {
	r := randutil.New(seed)

	g := &Genome{
		TagSize:   16,
		EpochSize: 4,
	}

	// Magic byte — pseudo-random, different each session.
	g.MagicByte = r.Bytes(1)[0]

	// Nonce size: 12 or 24 bytes.
	if r.Intn(2) == 0 {
		g.NonceSize = 12
	} else {
		g.NonceSize = 24
	}

	// Length encoding.
	g.LengthEnc = LengthEncoding(r.Intn(4))
	if g.LengthEnc == LenXORUint16 {
		g.LengthXORMask = uint16(r.Uint32())
	}

	// Core fields.
	codec := NewLengthCodec(g.LengthEnc, g.LengthXORMask)
	lengthFieldSize := 0
	if codec.FixedSize() {
		lengthFieldSize = codec.MaxSize()
	}

	fields := []FieldSpec{
		{ID: FieldNonce, Size: g.NonceSize},
		{ID: FieldLength, Size: lengthFieldSize}, // 0 for varint
		{ID: FieldPadLen, Size: 1},               // padding length fits in 1 byte
		{ID: FieldTag, Size: g.TagSize},
		{ID: FieldEpoch, Size: g.EpochSize},
	}

	// Add 0-3 decoy fields.
	numDecoys := r.Intn(4)
	for i := 0; i < numDecoys; i++ {
		decoySize := r.Intn(8) + 1 // 1-8 bytes
		mask := r.Bytes(decoySize)
		fields = append(fields, FieldSpec{
			ID:      FieldDecoy,
			Size:    decoySize,
			Decoy:   true,
			XORMask: mask,
		})
	}

	// Shuffle field order (Fisher-Yates).
	r.Shuffle(len(fields), func(i, j int) {
		fields[i], fields[j] = fields[j], fields[i]
	})

	g.Fields = fields

	// Padding range.
	g.PadMin = r.Intn(16)                // 0-15
	g.PadMax = g.PadMin + r.Intn(64) + 1 // at least 1 more than PadMin

	// Stream-mode wagon size range (plaintext bytes inside AEAD).
	// muxMSS=1200 mirrors mux.MSS; inline to avoid a morph→mux import cycle.
	// Max mux.Command size ≈ muxMSS+9 (CmdData header), so WagonMin must leave
	// room for that plus the 2-byte RealLen prefix. WagonMax is bounded so
	// wagon + AEAD tag + worst-case morph header + padding stays under UDP MTU.
	const muxMSS = 1200
	g.WagonMin = muxMSS + 16 + r.Intn(16)     // 1216..1231
	g.WagonMax = g.WagonMin + r.Intn(80) + 24 // +24..+103 → max ≈ 1334

	return g
}

// HeaderSize returns the fixed part of the header size (excluding variable-length fields).
// For genomes with varint length encoding, the actual header may be 1-3 bytes larger
// depending on the payload length value.
func (g *Genome) HeaderSize() int {
	size := 1 // magic byte
	for _, f := range g.Fields {
		if f.Size > 0 {
			size += f.Size
		} else {
			// Variable-length field (varint) — use max size for budget.
			size += 3
		}
	}
	return size
}

// MinHeaderSize returns the minimum possible header size.
func (g *Genome) MinHeaderSize() int {
	size := 1 // magic byte
	for _, f := range g.Fields {
		if f.Size > 0 {
			size += f.Size
		} else {
			size += 1 // varint minimum
		}
	}
	return size
}

// MaxOverhead returns the maximum total overhead per packet:
// magic + header fields + max padding + AEAD overhead.
func (g *Genome) MaxOverhead(aeadOverhead int) int {
	return g.HeaderSize() + g.PadMax + aeadOverhead
}

// String returns a human-readable representation of the genome (for debug logging).
func (g *Genome) String() string {
	fieldOrder := ""
	for i, f := range g.Fields {
		if i > 0 {
			fieldOrder += ","
		}
		switch f.ID {
		case FieldNonce:
			fieldOrder += "N"
		case FieldLength:
			fieldOrder += "L"
		case FieldPadLen:
			fieldOrder += "P"
		case FieldTag:
			fieldOrder += "T"
		case FieldEpoch:
			fieldOrder += "E"
		case FieldDecoy:
			fieldOrder += fmt.Sprintf("D%d", f.Size)
		}
	}
	return fmt.Sprintf("Genome{magic=0x%02x nonce=%d lenEnc=%d fields=[%s] pad=[%d,%d] wagon=[%d,%d]}",
		g.MagicByte, g.NonceSize, g.LengthEnc, fieldOrder, g.PadMin, g.PadMax, g.WagonMin, g.WagonMax)
}

// Equal checks if two genomes are identical.
func (g *Genome) Equal(other *Genome) bool {
	if g.MagicByte != other.MagicByte ||
		g.NonceSize != other.NonceSize ||
		g.LengthEnc != other.LengthEnc ||
		g.LengthXORMask != other.LengthXORMask ||
		g.PadMin != other.PadMin ||
		g.PadMax != other.PadMax ||
		g.TagSize != other.TagSize ||
		g.EpochSize != other.EpochSize ||
		g.WagonMin != other.WagonMin ||
		g.WagonMax != other.WagonMax ||
		len(g.Fields) != len(other.Fields) {
		return false
	}
	for i, f := range g.Fields {
		o := other.Fields[i]
		if f.ID != o.ID || f.Size != o.Size || f.Decoy != o.Decoy {
			return false
		}
	}
	return true
}

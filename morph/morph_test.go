package morph

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"
)

// --- Length codec tests ---

func TestLengthCodecRoundTrip(t *testing.T) {
	codecs := []struct {
		name  string
		codec LengthCodec
	}{
		{"BE", NewLengthCodec(LenUint16BE, 0)},
		{"LE", NewLengthCodec(LenUint16LE, 0)},
		{"Varint", NewLengthCodec(LenVarint, 0)},
		{"XOR", NewLengthCodec(LenXORUint16, 0xABCD)},
	}

	values := []uint16{0, 1, 127, 128, 255, 256, 1000, 0x7FFF, 0xFFFF}

	for _, tc := range codecs {
		for _, v := range values {
			buf := make([]byte, tc.codec.MaxSize())
			n := tc.codec.Encode(v, buf)
			decoded, dn, err := tc.codec.Decode(buf[:n])
			if err != nil {
				t.Fatalf("%s: decode error for %d: %v", tc.name, v, err)
			}
			if decoded != v {
				t.Fatalf("%s: roundtrip failed: encoded %d, decoded %d", tc.name, v, decoded)
			}
			if dn != n {
				t.Fatalf("%s: byte count mismatch: encoded %d bytes, decoded %d bytes", tc.name, n, dn)
			}
		}
	}
}

// --- Genome tests ---

func TestGenomeDeterminism(t *testing.T) {
	seed := []byte("genome-determinism-test-seed-0123")
	g1 := Derive(seed)
	g2 := Derive(seed)
	if !g1.Equal(g2) {
		t.Fatalf("same seed produced different genomes:\n  %s\n  %s", g1, g2)
	}
}

func TestGenomeDifferentSeeds(t *testing.T) {
	g1 := Derive([]byte("seed-alpha-0001"))
	g2 := Derive([]byte("seed-beta-0002"))

	// They could theoretically be equal, but extremely unlikely.
	if g1.Equal(g2) {
		t.Fatal("different seeds produced identical genomes")
	}
}

func TestGenomeFieldCount(t *testing.T) {
	// Core fields: Nonce, Length, PadLen, Tag, Epoch = 5.
	// Plus 0-3 decoys = 5-8 total.
	for i := 0; i < 100; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		g := Derive(seed)
		if len(g.Fields) < 5 || len(g.Fields) > 8 {
			t.Fatalf("genome has %d fields (expected 5-8): %s", len(g.Fields), g)
		}
	}
}

func TestGenomeNonceSize(t *testing.T) {
	saw12, saw24 := false, false
	for i := 0; i < 200; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		g := Derive(seed)
		switch g.NonceSize {
		case 12:
			saw12 = true
		case 24:
			saw24 = true
		default:
			t.Fatalf("unexpected nonce size %d", g.NonceSize)
		}
	}
	if !saw12 || !saw24 {
		t.Fatal("expected both nonce sizes (12, 24) to appear in 200 trials")
	}
}

func TestGenomeLengthEncodings(t *testing.T) {
	seen := map[LengthEncoding]bool{}
	for i := 0; i < 500; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		g := Derive(seed)
		seen[g.LengthEnc] = true
	}
	for _, enc := range []LengthEncoding{LenUint16BE, LenUint16LE, LenVarint, LenXORUint16} {
		if !seen[enc] {
			t.Fatalf("LengthEncoding %d never appeared in 500 trials", enc)
		}
	}
}

func TestGenomePadding(t *testing.T) {
	for i := 0; i < 100; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		g := Derive(seed)
		if g.PadMin < 0 || g.PadMin > 15 {
			t.Fatalf("PadMin = %d, out of range [0,15]", g.PadMin)
		}
		if g.PadMax <= g.PadMin {
			t.Fatalf("PadMax (%d) <= PadMin (%d)", g.PadMax, g.PadMin)
		}
	}
}

// --- Frame encode/decode tests ---

func TestFrameRoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		g := Derive(seed)

		enc := NewEncoder(g)
		dec := NewDecoder(g)

		// Build a frame with realistic data.
		nonce := make([]byte, g.NonceSize)
		rand.Read(nonce)

		ciphertext := make([]byte, 100+i)
		rand.Read(ciphertext)

		tag := make([]byte, 16)
		rand.Read(tag)

		padding, err := GeneratePadding(g.PadMin, g.PadMax)
		if err != nil {
			t.Fatal(err)
		}

		original := &Frame{
			Nonce:      nonce,
			Epoch:      uint32(42 + i),
			Ciphertext: ciphertext,
			Tag:        tag,
			Padding:    padding,
		}

		wire, err := enc.Encode(original)
		if err != nil {
			t.Fatalf("seed %d: encode error: %v", i, err)
		}

		// Wire should start with magic byte.
		if wire[0] != g.MagicByte {
			t.Fatalf("wire[0] = 0x%02x, want 0x%02x", wire[0], g.MagicByte)
		}

		decoded, err := dec.Decode(wire)
		if err != nil {
			t.Fatalf("seed %d: decode error: %v\ngenome: %s", i, err, g)
		}

		if !bytes.Equal(decoded.Nonce, original.Nonce) {
			t.Fatalf("nonce mismatch")
		}
		if decoded.Epoch != original.Epoch {
			t.Fatalf("epoch mismatch: got %d, want %d", decoded.Epoch, original.Epoch)
		}
		if !bytes.Equal(decoded.Ciphertext, original.Ciphertext) {
			t.Fatalf("ciphertext mismatch")
		}
		if !bytes.Equal(decoded.Tag, original.Tag) {
			t.Fatalf("tag mismatch")
		}
	}
}

func TestFrameWrongMagic(t *testing.T) {
	g := Derive([]byte("wrong-magic-test"))
	dec := NewDecoder(g)

	raw := []byte{g.MagicByte ^ 0xFF, 0, 0, 0}
	_, err := dec.Decode(raw)
	if err == nil {
		t.Fatal("expected error on wrong magic byte")
	}
}

func TestFrameEntropy(t *testing.T) {
	seed := []byte("entropy-test-seed-32bytes!!!!!!!!")
	g := Derive(seed)
	enc := NewEncoder(g)

	var allBytes []byte
	for i := 0; i < 10000; i++ {
		nonce := make([]byte, g.NonceSize)
		rand.Read(nonce)
		ciphertext := make([]byte, 64)
		rand.Read(ciphertext)
		tag := make([]byte, 16)
		rand.Read(tag)
		padding, _ := GeneratePadding(g.PadMin, g.PadMax)

		frame := &Frame{
			Nonce:      nonce,
			Epoch:      uint32(i),
			Ciphertext: ciphertext,
			Tag:        tag,
			Padding:    padding,
		}
		wire, err := enc.Encode(frame)
		if err != nil {
			t.Fatal(err)
		}
		allBytes = append(allBytes, wire...)
	}

	entropy := shannonEntropy(allBytes)
	if entropy < 7.9 {
		t.Fatalf("entropy = %.4f bits/byte, want >= 7.9", entropy)
	}
	t.Logf("wire entropy: %.4f bits/byte (%d bytes sampled)", entropy, len(allBytes))
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// --- Padding tests ---

func TestGeneratePadding(t *testing.T) {
	for i := 0; i < 100; i++ {
		pad, err := GeneratePadding(5, 20)
		if err != nil {
			t.Fatal(err)
		}
		if len(pad) < 5 || len(pad) > 20 {
			t.Fatalf("padding length %d outside [5,20]", len(pad))
		}
	}
}

func TestGeneratePaddingZero(t *testing.T) {
	pad, err := GeneratePadding(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pad != nil && len(pad) != 0 {
		t.Fatalf("expected nil/empty padding for (0,0), got %d bytes", len(pad))
	}
}

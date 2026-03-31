package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveSessionKeys(t *testing.T) {
	psk := []byte("super-secret-pre-shared-key-1234")

	k1, err := DeriveSessionKeys(psk, nil, CipherChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1.AEADKey) != 32 {
		t.Fatalf("AEAD key length = %d, want 32", len(k1.AEADKey))
	}
	if len(k1.GenomeSeed) != 32 {
		t.Fatalf("genome seed length = %d, want 32", len(k1.GenomeSeed))
	}
	if len(k1.NonceBase) != 24 {
		t.Fatalf("nonce base length = %d, want 24", len(k1.NonceBase))
	}

	// Determinism.
	k2, err := DeriveSessionKeys(psk, nil, CipherChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.AEADKey, k2.AEADKey) {
		t.Fatal("non-deterministic AEAD key")
	}
	if !bytes.Equal(k1.GenomeSeed, k2.GenomeSeed) {
		t.Fatal("non-deterministic genome seed")
	}

	// Different PSKs → different keys.
	k3, err := DeriveSessionKeys([]byte("another-psk-value-here!!"), nil, CipherChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1.AEADKey, k3.AEADKey) {
		t.Fatal("different PSKs produced same AEAD key")
	}
}

func TestDeriveShortPSK(t *testing.T) {
	_, err := DeriveSessionKeys([]byte("short"), nil, CipherChaCha20Poly1305)
	if err == nil {
		t.Fatal("expected error for short PSK")
	}
}

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	for _, suite := range []CipherSuite{CipherChaCha20Poly1305, CipherAES256GCM} {
		aead, err := NewAEAD(key, suite)
		if err != nil {
			t.Fatalf("suite %d: %v", suite, err)
		}

		plaintext := []byte("hello, chameleon protocol!")
		nonce := make([]byte, aead.NonceSize())
		for i := range nonce {
			nonce[i] = byte(i + 100)
		}

		ciphertext := aead.Seal(nil, nonce, plaintext, nil)
		decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			t.Fatalf("suite %d: decrypt failed: %v", suite, err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("suite %d: decrypted != plaintext", suite)
		}
	}
}

func TestAEADTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := NewAEAD(key, CipherChaCha20Poly1305)
	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, []byte("test"), nil)
	ct[0] ^= 0xff
	_, err := aead.Open(nil, nonce, ct, nil)
	if err == nil {
		t.Fatal("expected decryption failure on tampered ciphertext")
	}
}

func TestBuildNonce(t *testing.T) {
	base := make([]byte, 24)
	for i := range base {
		base[i] = byte(i + 1)
	}

	n12 := BuildNonce(base, 42, 12)
	if len(n12) != 12 {
		t.Fatalf("nonce length = %d, want 12", len(n12))
	}
	// Last 4 bytes should be epoch=42 in big-endian.
	if n12[11] != 42 || n12[10] != 0 || n12[9] != 0 || n12[8] != 0 {
		t.Fatalf("epoch not correctly placed in 12-byte nonce: %x", n12)
	}

	n24 := BuildNonce(base, 0x01020304, 24)
	if len(n24) != 24 {
		t.Fatalf("nonce length = %d, want 24", len(n24))
	}
	if n24[20] != 0x01 || n24[21] != 0x02 || n24[22] != 0x03 || n24[23] != 0x04 {
		t.Fatalf("epoch not correctly placed in 24-byte nonce: %x", n24)
	}
}

func TestXAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	aead, err := NewXAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	if aead.NonceSize() != 24 {
		t.Fatalf("XChaCha nonce size = %d, want 24", aead.NonceSize())
	}
	nonce := make([]byte, 24)
	ct := aead.Seal(nil, nonce, []byte("xchacha test"), nil)
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "xchacha test" {
		t.Fatalf("got %q", pt)
	}
}

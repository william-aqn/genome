// Package crypto provides AEAD encryption and HKDF key derivation for the Chameleon protocol.
package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// CipherSuite identifies the AEAD algorithm.
type CipherSuite int

const (
	CipherChaCha20Poly1305 CipherSuite = iota
	CipherAES256GCM
)

// SessionKeys holds all keying material derived from a PSK for one session.
type SessionKeys struct {
	AEADKey    []byte      // 32 bytes
	GenomeSeed []byte      // 32 bytes
	NonceBase  []byte      // 24 bytes — prefix for nonce construction
	Suite      CipherSuite // chosen AEAD algorithm
}

// DeriveSessionKeys derives session keying material from a PSK using HKDF-SHA256.
// salt can be nil for PSK-only mode (no handshake).
func DeriveSessionKeys(psk []byte, salt []byte, suite CipherSuite) (*SessionKeys, error) {
	if len(psk) < 16 {
		return nil, fmt.Errorf("crypto: PSK too short (%d bytes, minimum 16)", len(psk))
	}

	prk := hkdf.Extract(sha256.New, psk, salt)

	aeadKey, err := expand(prk, "chameleon-aead-key", 32)
	if err != nil {
		return nil, fmt.Errorf("crypto: deriving AEAD key: %w", err)
	}

	genomeSeed, err := expand(prk, "chameleon-genome-seed", 32)
	if err != nil {
		return nil, fmt.Errorf("crypto: deriving genome seed: %w", err)
	}

	nonceBase, err := expand(prk, "chameleon-nonce-base", 24)
	if err != nil {
		return nil, fmt.Errorf("crypto: deriving nonce base: %w", err)
	}

	return &SessionKeys{
		AEADKey:    aeadKey,
		GenomeSeed: genomeSeed,
		NonceBase:  nonceBase,
		Suite:      suite,
	}, nil
}

func expand(prk []byte, info string, length int) ([]byte, error) {
	r := hkdf.Expand(sha256.New, prk, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

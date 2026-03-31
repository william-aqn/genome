package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// NewAEAD creates an AEAD cipher for the given key and suite.
// For ChaCha20-Poly1305 with 24-byte nonces, use NewXAEAD.
func NewAEAD(key []byte, suite CipherSuite) (cipher.AEAD, error) {
	switch suite {
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("crypto: AES cipher: %w", err)
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("crypto: unknown cipher suite %d", suite)
	}
}

// NewXAEAD creates an XChaCha20-Poly1305 AEAD with 24-byte nonces.
func NewXAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// NonceSize returns the expected nonce size for the given suite and nonceLen.
// nonceLen is the genome-derived nonce size (12 or 24).
func NonceSize(suite CipherSuite, nonceLen int) int {
	if nonceLen == 24 {
		return 24 // XChaCha20-Poly1305
	}
	switch suite {
	case CipherChaCha20Poly1305:
		return chacha20poly1305.NonceSize // 12
	case CipherAES256GCM:
		return 12 // standard GCM nonce
	default:
		return 12
	}
}

// BuildNonce constructs a nonce from a base prefix and an epoch counter.
// The nonce is nonceSize bytes: base[:nonceSize-4] || epoch (big-endian 4 bytes).
func BuildNonce(base []byte, epoch uint32, nonceSize int) []byte {
	nonce := make([]byte, nonceSize)
	prefixLen := nonceSize - 4
	if prefixLen > 0 && len(base) >= prefixLen {
		copy(nonce[:prefixLen], base[:prefixLen])
	}
	nonce[nonceSize-4] = byte(epoch >> 24)
	nonce[nonceSize-3] = byte(epoch >> 16)
	nonce[nonceSize-2] = byte(epoch >> 8)
	nonce[nonceSize-1] = byte(epoch)
	return nonce
}

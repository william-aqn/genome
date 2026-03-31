// Package randutil provides a deterministic PRNG seeded from a byte slice.
// It uses SHA-256 in counter mode to produce a reproducible stream of
// pseudorandom bytes, independent of Go version or platform.
package randutil

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// DRand is a deterministic pseudorandom number generator.
// It produces a reproducible byte stream from an initial seed
// using SHA-256 in counter mode: block_i = SHA-256(seed || i).
type DRand struct {
	seed    [32]byte
	counter uint64
	buf     [32]byte
	pos     int // next unread byte in buf
}

// New creates a DRand seeded from the provided bytes.
// The seed is hashed with SHA-256 to normalize length.
func New(seed []byte) *DRand {
	r := &DRand{
		seed: sha256.Sum256(seed),
		pos:  32, // force refill on first use
	}
	return r
}

// refill generates the next 32-byte block.
func (r *DRand) refill() {
	var input [40]byte
	copy(input[:32], r.seed[:])
	binary.LittleEndian.PutUint64(input[32:], r.counter)
	r.buf = sha256.Sum256(input[:])
	r.counter++
	r.pos = 0
}

// Bytes returns n pseudorandom bytes.
func (r *DRand) Bytes(n int) []byte {
	out := make([]byte, n)
	off := 0
	for off < n {
		if r.pos >= 32 {
			r.refill()
		}
		copied := copy(out[off:], r.buf[r.pos:])
		r.pos += copied
		off += copied
	}
	return out
}

// Uint32 returns a pseudorandom uint32.
func (r *DRand) Uint32() uint32 {
	b := r.Bytes(4)
	return binary.LittleEndian.Uint32(b)
}

// Uint64 returns a pseudorandom uint64.
func (r *DRand) Uint64() uint64 {
	b := r.Bytes(8)
	return binary.LittleEndian.Uint64(b)
}

// Intn returns a pseudorandom int in [0, n) with no modulo bias.
func (r *DRand) Intn(n int) int {
	if n <= 0 {
		panic("randutil: invalid argument to Intn")
	}
	if n == 1 {
		return 0
	}
	// Rejection sampling to eliminate modulo bias.
	un := uint32(n)
	threshold := (math.MaxUint32 - un + 1) % un
	for {
		v := r.Uint32()
		if v >= threshold {
			return int(v % un)
		}
	}
}

// Float64 returns a pseudorandom float64 in [0.0, 1.0).
func (r *DRand) Float64() float64 {
	return float64(r.Uint64()>>11) / (1 << 53)
}

// Shuffle performs a Fisher-Yates shuffle on n elements.
func (r *DRand) Shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		swap(i, j)
	}
}

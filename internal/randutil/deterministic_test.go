package randutil

import (
	"testing"
)

func TestDeterminism(t *testing.T) {
	seed := []byte("test-seed-chameleon")
	r1 := New(seed)
	r2 := New(seed)

	for i := 0; i < 1000; i++ {
		if r1.Uint32() != r2.Uint32() {
			t.Fatalf("non-deterministic at iteration %d", i)
		}
	}
}

func TestDifferentSeeds(t *testing.T) {
	r1 := New([]byte("seed-a"))
	r2 := New([]byte("seed-b"))

	same := 0
	for i := 0; i < 100; i++ {
		if r1.Uint32() == r2.Uint32() {
			same++
		}
	}
	if same > 5 {
		t.Fatalf("different seeds produced %d/100 identical values", same)
	}
}

func TestIntn(t *testing.T) {
	r := New([]byte("intn-test"))
	for _, n := range []int{1, 2, 3, 5, 10, 100, 1000, 65536} {
		for i := 0; i < 1000; i++ {
			v := r.Intn(n)
			if v < 0 || v >= n {
				t.Fatalf("Intn(%d) = %d, out of range", n, v)
			}
		}
	}
}

func TestIntnDistribution(t *testing.T) {
	r := New([]byte("distribution"))
	n := 4
	counts := make([]int, n)
	total := 40000
	for i := 0; i < total; i++ {
		counts[r.Intn(n)]++
	}
	expected := total / n
	for i, c := range counts {
		deviation := float64(c-expected) / float64(expected)
		if deviation > 0.05 || deviation < -0.05 {
			t.Fatalf("bucket %d: count %d, expected ~%d (deviation %.2f%%)", i, c, expected, deviation*100)
		}
	}
}

func TestShuffle(t *testing.T) {
	r := New([]byte("shuffle-test"))
	a := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	r.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })

	// Check it's a valid permutation.
	seen := make(map[int]bool)
	for _, v := range a {
		if v < 0 || v >= 10 {
			t.Fatalf("invalid value %d in shuffle result", v)
		}
		if seen[v] {
			t.Fatalf("duplicate value %d in shuffle result", v)
		}
		seen[v] = true
	}

	// Verify determinism.
	r2 := New([]byte("shuffle-test"))
	b := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	r2.Shuffle(len(b), func(i, j int) { b[i], b[j] = b[j], b[i] })
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("shuffle not deterministic at index %d", i)
		}
	}
}

func TestBytes(t *testing.T) {
	r := New([]byte("bytes-test"))
	b := r.Bytes(1000)
	if len(b) != 1000 {
		t.Fatalf("expected 1000 bytes, got %d", len(b))
	}
	// Basic entropy check: not all zeros.
	zeros := 0
	for _, v := range b {
		if v == 0 {
			zeros++
		}
	}
	if zeros > 20 {
		t.Fatalf("suspiciously many zeros: %d/1000", zeros)
	}
}

func TestFloat64(t *testing.T) {
	r := New([]byte("float-test"))
	for i := 0; i < 10000; i++ {
		v := r.Float64()
		if v < 0.0 || v >= 1.0 {
			t.Fatalf("Float64() = %f, out of [0,1)", v)
		}
	}
}

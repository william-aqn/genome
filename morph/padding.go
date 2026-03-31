package morph

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand/v2"
)

// GeneratePadding creates random padding bytes of a length chosen
// uniformly in [padMin, padMax] using crypto/rand.
func GeneratePadding(padMin, padMax int) ([]byte, error) {
	if padMax < padMin || padMin < 0 {
		return nil, nil
	}
	n := padMin
	if padMax > padMin {
		n += mrand.IntN(padMax - padMin + 1)
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("morph: generating padding: %w", err)
	}
	return buf, nil
}

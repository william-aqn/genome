// Package transport provides the UDP tunnel with morph framing and AEAD encryption.
package transport

import (
	"math/rand/v2"
	"time"
)

// Shaper adds timing jitter to outbound packets.
type Shaper struct {
	jitterMin time.Duration
	jitterMax time.Duration
	enabled   bool
}

// NewShaper creates a traffic shaper. If maxJitter <= 0, shaping is disabled.
func NewShaper(minJitter, maxJitter time.Duration) *Shaper {
	if maxJitter <= 0 {
		return &Shaper{enabled: false}
	}
	return &Shaper{
		jitterMin: minJitter,
		jitterMax: maxJitter,
		enabled:   true,
	}
}

// Delay waits a random duration in [jitterMin, jitterMax].
func (s *Shaper) Delay() {
	if !s.enabled {
		return
	}
	d := s.jitterMin
	if s.jitterMax > s.jitterMin {
		d += time.Duration(rand.Int64N(int64(s.jitterMax - s.jitterMin)))
	}
	if d > 0 {
		time.Sleep(d)
	}
}

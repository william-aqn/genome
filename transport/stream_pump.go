package transport

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"time"
)

// ErrPumpClosed is returned by Enqueue after the pump has been closed.
var ErrPumpClosed = errors.New("transport: stream pump closed")

// ErrPayloadTooLarge is returned by Enqueue when a payload would not fit in
// the smallest possible wagon (WagonMin - 2 bytes of body).
var ErrPayloadTooLarge = errors.New("transport: payload exceeds wagon capacity")

// StreamPump emits a constant stream of fixed-shape "wagons" through the tunnel.
// Each wagon is a plaintext of genome-derived size carrying either real mux
// payload (length-prefixed) or pure random chaff. The overall emission rate
// drifts inside [minRate, maxRate] bytes/sec; when the send queue exceeds a
// threshold, the pump bursts beyond the envelope to drain real data "as is".
//
// Wire layout of each wagon plaintext:
//
//	[RealLen uint16 BE][RealBytes RealLen][RandomFiller to wagon size]
//
// RealLen==0 marks a pure-chaff wagon; the receiver silently drops it.
type StreamPump struct {
	tunnel         *Tunnel
	minRate        int // bytes/sec (plaintext)
	maxRate        int // bytes/sec (plaintext)
	wagonMin       int
	wagonMax       int
	burstThreshold int

	queue chan []byte

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	started   sync.Once

	onBurstTick func() // optional callback; invoked once per burst-mode wagon
}

const (
	// streamQueueCap caps the pending mux commands awaiting a wagon. A small
	// cap is enough because mux enforces its own flow control above us.
	streamQueueCap = 128
	// streamBurstFraction: when queue ≥ streamQueueCap/streamBurstFraction, pump
	// drops the rate limit and drains "as is".
	streamBurstFraction = 2
	// streamRateDriftInterval controls how often currentRate is nudged.
	streamRateDriftInterval = 1 * time.Second
	// streamMaxCatchUp bounds how far behind schedule the pump will fall
	// before resynchronizing nextSendAt to now (avoids perma-burst on hiccups).
	streamMaxCatchUp = 1 * time.Second
)

// NewStreamPump creates a pump bound to the given tunnel with the supplied
// rate envelope. minRate and maxRate are in plaintext bytes per second;
// both must be > 0 and minRate ≤ maxRate. Wagon sizes come from the
// tunnel's genome (g.WagonMin .. g.WagonMax).
func NewStreamPump(t *Tunnel, minRate, maxRate int) (*StreamPump, error) {
	if t == nil {
		return nil, fmt.Errorf("transport: stream pump needs a tunnel")
	}
	if minRate <= 0 || maxRate <= 0 || minRate > maxRate {
		return nil, fmt.Errorf("transport: invalid stream rate envelope [%d,%d]", minRate, maxRate)
	}
	g := t.genome
	if g == nil || g.WagonMin <= 2 || g.WagonMax < g.WagonMin {
		return nil, fmt.Errorf("transport: genome has invalid wagon range")
	}
	return &StreamPump{
		tunnel:         t,
		minRate:        minRate,
		maxRate:        maxRate,
		wagonMin:       g.WagonMin,
		wagonMax:       g.WagonMax,
		burstThreshold: streamQueueCap / streamBurstFraction,
		queue:          make(chan []byte, streamQueueCap),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}, nil
}

// Start launches the pump goroutine. Safe to call multiple times; only
// the first call has effect.
func (p *StreamPump) Start() {
	p.started.Do(func() {
		go p.pumpLoop()
	})
}

// Enqueue places a payload into the pump queue. It blocks while the queue
// is full (respecting mux-level flow control) and returns ErrPumpClosed
// if the pump has been stopped. Payloads that don't fit in the minimum
// wagon (WagonMin-2 bytes) are rejected with ErrPayloadTooLarge.
func (p *StreamPump) Enqueue(payload []byte) error {
	// Fast path: fail closed pumps immediately so callers don't silently
	// enqueue into a channel that will never drain. Without this the select
	// below is racy when both branches are ready at once.
	select {
	case <-p.stop:
		return ErrPumpClosed
	default:
	}
	if len(payload) > p.wagonMin-2 {
		return ErrPayloadTooLarge
	}
	// Defensive copy so callers can reuse their buffer.
	buf := make([]byte, len(payload))
	copy(buf, payload)
	select {
	case p.queue <- buf:
		return nil
	case <-p.stop:
		return ErrPumpClosed
	}
}

// Close stops the pump goroutine and blocks until it exits. Safe to
// call multiple times.
func (p *StreamPump) Close() error {
	p.closeOnce.Do(func() {
		close(p.stop)
	})
	<-p.done
	return nil
}

// SetBurstCallback installs an optional observer notified when the pump
// emits a wagon in burst mode. Used by the dashboard / tests to verify
// that burst kicks in under load.
func (p *StreamPump) SetBurstCallback(fn func()) {
	p.onBurstTick = fn
}

// pumpLoop is the single writer goroutine. Everything funnels through here.
func (p *StreamPump) pumpLoop() {
	defer close(p.done)

	currentRate := p.randRate()
	nextDrift := time.Now().Add(streamRateDriftInterval)
	nextSendAt := time.Now()

	for {
		// Rate drift (slow random walk within the envelope).
		if now := time.Now(); now.After(nextDrift) {
			currentRate = p.driftRate(currentRate)
			nextDrift = now.Add(streamRateDriftInterval)
		}

		// Burst: skip the rate-limit wait if the queue is backed up.
		burst := len(p.queue) >= p.burstThreshold
		if !burst {
			wait := time.Until(nextSendAt)
			if wait > 0 {
				t := time.NewTimer(wait)
				select {
				case <-t.C:
				case <-p.stop:
					t.Stop()
					return
				}
			} else {
				// Still check for stop to ensure responsive shutdown.
				select {
				case <-p.stop:
					return
				default:
				}
			}
		} else {
			select {
			case <-p.stop:
				return
			default:
			}
		}

		// Fresh wagon size from the genome envelope.
		wagonSize := p.wagonMin
		if p.wagonMax > p.wagonMin {
			wagonSize += mrand.IntN(p.wagonMax - p.wagonMin + 1)
		}

		// Before the server learns its peer the pump has nowhere to send.
		// Hold the cadence but don't consume the queue or emit — otherwise
		// we'd either spam drops or lose real payloads.
		if !p.tunnel.hasPeer() {
			p.scheduleNext(&nextSendAt, wagonSize, currentRate)
			continue
		}

		// Pull one real payload (non-blocking).
		var payload []byte
		select {
		case payload = <-p.queue:
		default:
		}

		wagon, err := buildWagon(payload, wagonSize)
		if err != nil {
			// Should not happen: Enqueue enforces payload size.
			if p.tunnel.onDrop != nil {
				p.tunnel.onDrop("wagon-build", err)
			}
			continue
		}

		if err := p.tunnel.sendRaw(wagon); err != nil {
			if p.tunnel.onDrop != nil {
				p.tunnel.onDrop("wagon-send", err)
			}
		}

		if burst && p.onBurstTick != nil {
			p.onBurstTick()
		}

		// Schedule the next send. In burst mode interval is still computed
		// so that when the queue drains we're back on schedule.
		p.scheduleNext(&nextSendAt, wagonSize, currentRate)
	}
}

// scheduleNext advances nextSendAt by one interval. The anti-drift clamp
// keeps the pump from entering permanent burst after a long hiccup
// (e.g. sleep, peer discovery, debugger pause).
func (p *StreamPump) scheduleNext(nextSendAt *time.Time, wagonSize, currentRate int) {
	interval := time.Duration(int64(wagonSize) * int64(time.Second) / int64(currentRate))
	if interval <= 0 {
		interval = time.Microsecond
	}
	*nextSendAt = nextSendAt.Add(interval)
	if time.Since(*nextSendAt) > streamMaxCatchUp {
		*nextSendAt = time.Now()
	}
}

func (p *StreamPump) randRate() int {
	if p.maxRate == p.minRate {
		return p.minRate
	}
	return p.minRate + mrand.IntN(p.maxRate-p.minRate+1)
}

// driftRate nudges rate by up to ±(max-min)/8, clamped to the envelope.
func (p *StreamPump) driftRate(current int) int {
	span := p.maxRate - p.minRate
	if span <= 0 {
		return p.minRate
	}
	step := span / 8
	if step < 1 {
		step = 1
	}
	delta := mrand.IntN(2*step+1) - step // -step..+step
	next := current + delta
	if next < p.minRate {
		next = p.minRate
	}
	if next > p.maxRate {
		next = p.maxRate
	}
	return next
}

// buildWagon packs a plaintext wagon of exactly `size` bytes.
// payload may be nil/empty (pure chaff) or up to size-2 bytes of real data.
func buildWagon(payload []byte, size int) ([]byte, error) {
	if size < 2 {
		return nil, fmt.Errorf("transport: wagon size %d too small", size)
	}
	if len(payload) > size-2 {
		return nil, ErrPayloadTooLarge
	}
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	if len(payload) > 0 {
		copy(buf[2:], payload)
	}
	if tail := buf[2+len(payload):]; len(tail) > 0 {
		if _, err := crand.Read(tail); err != nil {
			return nil, fmt.Errorf("transport: chaff fill: %w", err)
		}
	}
	return buf, nil
}

// parseWagon extracts the real-payload slice from a wagon plaintext.
// Returns (payload, true) for a real wagon, (nil, false) for chaff, and
// a non-nil error for malformed wagons.
func parseWagon(plaintext []byte) ([]byte, bool, error) {
	if len(plaintext) < 2 {
		return nil, false, fmt.Errorf("transport: wagon too short (%d bytes)", len(plaintext))
	}
	realLen := int(binary.BigEndian.Uint16(plaintext[:2]))
	if realLen == 0 {
		return nil, false, nil
	}
	if 2+realLen > len(plaintext) {
		return nil, false, fmt.Errorf("transport: wagon overflow: RealLen=%d, have %d bytes", realLen, len(plaintext)-2)
	}
	return plaintext[2 : 2+realLen], true, nil
}

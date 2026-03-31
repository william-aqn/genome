package mux

import (
	"sync"
	"time"
)

const (
	// initialCWND is the initial congestion window (in bytes).
	initialCWND = 32 * 1024 // 32 KB
	// minCWND prevents cwnd from dropping to zero.
	minCWND = 4 * 1024 // 4 KB
	// maxCWND caps the congestion window.
	maxCWND = 4 * 1024 * 1024 // 4 MB
	// MSS is the maximum segment size used by the congestion controller.
	MSS = 1200
)

// CongestionController manages the sending rate for a tunnel.
type CongestionController interface {
	// OnAck is called when data is acknowledged.
	OnAck(ackedBytes uint32, rtt time.Duration)
	// OnLoss is called on detected packet loss (3 dup ACKs).
	OnLoss()
	// OnTimeout is called on retransmission timeout.
	OnTimeout()
	// SendWindow returns the current congestion window in bytes.
	SendWindow() uint32
}

// NewReno implements the TCP NewReno congestion control algorithm.
type NewReno struct {
	mu       sync.Mutex
	cwnd     uint32 // congestion window
	ssthresh uint32 // slow start threshold
	inRecov  bool   // in fast recovery
	recovSeq uint32 // sequence that ends fast recovery
}

// NewNewReno creates a NewReno congestion controller.
func NewNewReno() *NewReno {
	return &NewReno{
		cwnd:     initialCWND,
		ssthresh: maxCWND, // start in slow start
	}
}

// OnAck processes an acknowledgment.
func (nr *NewReno) OnAck(ackedBytes uint32, rtt time.Duration) {
	nr.mu.Lock()
	defer nr.mu.Unlock()

	if ackedBytes == 0 {
		return
	}

	if nr.cwnd < nr.ssthresh {
		// Slow start: increase cwnd by ackedBytes (approximately doubles per RTT).
		nr.cwnd += ackedBytes
	} else {
		// Congestion avoidance: increase cwnd by ~MSS per RTT.
		// Increment = MSS * ackedBytes / cwnd (additive increase).
		inc := uint32(MSS) * ackedBytes / nr.cwnd
		if inc == 0 {
			inc = 1
		}
		nr.cwnd += inc
	}

	if nr.cwnd > maxCWND {
		nr.cwnd = maxCWND
	}
}

// OnLoss is called on fast retransmit (3 dup ACKs).
func (nr *NewReno) OnLoss() {
	nr.mu.Lock()
	defer nr.mu.Unlock()

	if nr.inRecov {
		return // already in recovery
	}
	nr.inRecov = true
	nr.ssthresh = nr.cwnd / 2
	if nr.ssthresh < minCWND {
		nr.ssthresh = minCWND
	}
	nr.cwnd = nr.ssthresh + 3*MSS // fast recovery inflate
}

// OnTimeout is called on retransmission timeout (RTO).
func (nr *NewReno) OnTimeout() {
	nr.mu.Lock()
	defer nr.mu.Unlock()

	nr.ssthresh = nr.cwnd / 2
	if nr.ssthresh < minCWND {
		nr.ssthresh = minCWND
	}
	nr.cwnd = minCWND // reset to minimum
	nr.inRecov = false
}

// SendWindow returns the current congestion window.
func (nr *NewReno) SendWindow() uint32 {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	return nr.cwnd
}

// ExitRecovery exits fast recovery mode.
func (nr *NewReno) ExitRecovery() {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	if nr.inRecov {
		nr.cwnd = nr.ssthresh
		nr.inRecov = false
	}
}

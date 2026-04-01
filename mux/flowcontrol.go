package mux

import "sync"

const (
	// DefaultRecvWindow is the default receive window size in bytes.
	DefaultRecvWindow = 4 * 1024 * 1024 // 4 MB
	// MaxRecvWindow is the maximum receive window size.
	MaxRecvWindow = 64 * 1024 * 1024 // 64 MB
)

// FlowController manages per-stream flow control.
// Flow control is advisory — Consume never rejects data.
// The recv window is advertised in ACKs to pace the sender.
type FlowController struct {
	mu       sync.Mutex
	recvWin  uint32 // our advertised receive window
	consumed uint32 // bytes consumed but not yet released
	sendWin  uint32 // peer's advertised receive window
}

// NewFlowController creates a flow controller with the given initial receive window.
func NewFlowController(recvWindow uint32) *FlowController {
	return &FlowController{
		recvWin: recvWindow,
		sendWin: DefaultRecvWindow,
	}
}

// Consume decreases the receive window (data received from peer).
// Always accepts — flow control is advisory, never drops data.
func (fc *FlowController) Consume(n uint32) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if n > fc.recvWin {
		fc.recvWin = 0
	} else {
		fc.recvWin -= n
	}
	fc.consumed += n
	return true
}

// Release increases the receive window (data read by application).
func (fc *FlowController) Release(n uint32) uint32 {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.recvWin += n
	if fc.consumed >= n {
		fc.consumed -= n
	} else {
		fc.consumed = 0
	}
	if fc.recvWin > MaxRecvWindow {
		fc.recvWin = MaxRecvWindow
	}
	return fc.recvWin
}

// RecvWindow returns the current receive window to advertise.
func (fc *FlowController) RecvWindow() uint32 {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.recvWin
}

// UpdateSendWindow sets the peer's advertised receive window.
func (fc *FlowController) UpdateSendWindow(window uint32) {
	fc.mu.Lock()
	fc.sendWin = window
	fc.mu.Unlock()
}

// SendWindow returns how many bytes we are allowed to send.
func (fc *FlowController) SendWindow() uint32 {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.sendWin
}

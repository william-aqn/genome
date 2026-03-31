package mux

import "sync"

const (
	// DefaultRecvWindow is the default receive window size in bytes.
	DefaultRecvWindow = 256 * 1024 // 256 KB
	// MaxRecvWindow is the maximum receive window size.
	MaxRecvWindow = 4 * 1024 * 1024 // 4 MB
)

// FlowController manages per-stream flow control.
type FlowController struct {
	mu        sync.Mutex
	recvWin   uint32 // our advertised receive window (how much peer can send)
	consumed  uint32 // bytes consumed but not yet released
	sendWin   uint32 // peer's advertised receive window (how much we can send)
	sendReady chan struct{}
}

// NewFlowController creates a flow controller with the given initial receive window.
func NewFlowController(recvWindow uint32) *FlowController {
	return &FlowController{
		recvWin:   recvWindow,
		sendWin:   DefaultRecvWindow, // assume peer starts with default
		sendReady: make(chan struct{}, 1),
	}
}

// Consume decreases the receive window by n bytes (data received from peer).
// Returns false if the window would go negative (peer violated flow control).
func (fc *FlowController) Consume(n uint32) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if n > fc.recvWin {
		return false
	}
	fc.recvWin -= n
	fc.consumed += n
	return true
}

// Release increases the receive window by n bytes (data read by application).
// Returns the new window value to advertise to the peer.
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
	// Signal that send window may have opened.
	select {
	case fc.sendReady <- struct{}{}:
	default:
	}
}

// SendWindow returns how many bytes we are allowed to send.
func (fc *FlowController) SendWindow() uint32 {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.sendWin
}

// WaitSendReady returns a channel that signals when send window may have changed.
func (fc *FlowController) WaitSendReady() <-chan struct{} {
	return fc.sendReady
}

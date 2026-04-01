package mux

import "sync"

const (
	// DefaultRecvWindow is the default receive window size in bytes.
	DefaultRecvWindow = 4 * 1024 * 1024 // 4 MB
	// MaxRecvWindow is the maximum receive window size.
	MaxRecvWindow = 64 * 1024 * 1024 // 64 MB
)

// FlowController manages per-stream flow control.
type FlowController struct {
	mu        sync.Mutex
	recvWin   uint32 // our advertised receive window (how much peer can send)
	consumed  uint32 // bytes consumed but not yet released
	sendWin   uint32 // peer's advertised receive window (how much we can send)
	sendCond  *sync.Cond
}

// NewFlowController creates a flow controller with the given initial receive window.
func NewFlowController(recvWindow uint32) *FlowController {
	fc := &FlowController{
		recvWin: recvWindow,
		sendWin: DefaultRecvWindow,
	}
	fc.sendCond = sync.NewCond(&fc.mu)
	return fc
}

// Consume decreases the receive window by n bytes (data received from peer).
// Always accepts — flow control is advisory via ACK window, not a hard drop.
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
// Broadcasts to all goroutines waiting in WaitForSendWindow.
func (fc *FlowController) UpdateSendWindow(window uint32) {
	fc.mu.Lock()
	fc.sendWin = window
	fc.sendCond.Broadcast() // wake ALL waiting writers
	fc.mu.Unlock()
}

// SendWindow returns how many bytes we are allowed to send.
func (fc *FlowController) SendWindow() uint32 {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.sendWin
}

// WaitForSendWindow blocks until send window is > 0 or done is closed.
// Returns false if done was closed.
func (fc *FlowController) WaitForSendWindow(done <-chan struct{}) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Check done channel in a non-blocking way periodically.
	for fc.sendWin == 0 {
		select {
		case <-done:
			return false
		default:
		}
		// Use a goroutine to wake us if done closes.
		ch := make(chan struct{})
		go func() {
			select {
			case <-done:
				fc.sendCond.Broadcast()
			case <-ch:
			}
		}()
		fc.sendCond.Wait()
		close(ch)
	}
	return true
}

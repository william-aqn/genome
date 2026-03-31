package transport

import (
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"genome/morph"
)

const (
	// maxUDPSize is the maximum UDP datagram size we'll read.
	maxUDPSize = 65535
	// replayWindowSize is the anti-replay sliding window size.
	replayWindowSize = 256
	// defaultReadTimeout is the default UDP read deadline.
	defaultReadTimeout = 120 * time.Second
)

// Tunnel wraps a UDP connection with morph framing and AEAD encryption.
// It implements mux.TransportConn.
type Tunnel struct {
	conn      *net.UDPConn
	peer      *net.UDPAddr
	peerMu    sync.RWMutex
	aead      cipher.AEAD
	nonceBase []byte // prefix for nonce construction
	genome    *morph.Genome
	encoder   *morph.Encoder
	decoder   *morph.Decoder
	shaper    *Shaper
	epoch     atomic.Uint32

	// Anti-replay.
	replayMu  sync.Mutex
	replayMax uint32
	replayBmp [replayWindowSize / 32]uint32

	readTimeout time.Duration

	// onDrop is an optional callback for debugging dropped packets.
	onDrop func(reason string, err error)

	// Optional stats callbacks.
	onSend func(n int) // called with wire bytes sent
	onRecv func(n int) // called with wire bytes received
}

// NewTunnel creates a tunnel over an existing UDP connection.
// peer can be nil for servers that discover the peer from the first valid packet.
// nonceBase should be at least 24 bytes (derived from HKDF).
func NewTunnel(conn *net.UDPConn, peer *net.UDPAddr, aead cipher.AEAD,
	nonceBase []byte, genome *morph.Genome, shaper *Shaper) *Tunnel {

	t := &Tunnel{
		conn:        conn,
		peer:        peer,
		aead:        aead,
		nonceBase:   nonceBase,
		genome:      genome,
		encoder:     morph.NewEncoder(genome),
		decoder:     morph.NewDecoder(genome),
		shaper:      shaper,
		readTimeout: defaultReadTimeout,
	}
	// Start epoch at a random value so reconnects don't collide
	// with the server's replay window from a previous session.
	var rnd [4]byte
	crand.Read(rnd[:])
	t.epoch.Store(binary.BigEndian.Uint32(rnd[:]) >> 1) // top half of uint32 range
	return t
}

// SetDropCallback sets a callback invoked when a packet is dropped.
func (t *Tunnel) SetDropCallback(fn func(reason string, err error)) {
	t.onDrop = fn
}

// SetStatsCallbacks sets optional callbacks for byte counting.
func (t *Tunnel) SetStatsCallbacks(onSend, onRecv func(int)) {
	t.onSend = onSend
	t.onRecv = onRecv
}

// SetReadTimeout sets the UDP read deadline duration.
func (t *Tunnel) SetReadTimeout(d time.Duration) {
	t.readTimeout = d
}

// Send encrypts, frames, and sends payload through the tunnel.
func (t *Tunnel) Send(payload []byte) error {
	// Increment epoch.
	epoch := t.epoch.Add(1)

	// Build nonce: nonceBase[:nonceSize-4] || epoch (big-endian).
	nonceSize := t.aead.NonceSize()
	nonce := buildNonce(t.nonceBase, epoch, nonceSize)

	// Additional data: epoch bytes for binding.
	ad := epochBytes(epoch)

	// AEAD encrypt.
	sealed := t.aead.Seal(nil, nonce, payload, ad)

	// Split into ciphertext + tag.
	tagSize := t.aead.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	// Generate padding.
	padding, err := morph.GeneratePadding(t.genome.PadMin, t.genome.PadMax)
	if err != nil {
		return fmt.Errorf("transport: generating padding: %w", err)
	}

	// Build frame.
	frame := &morph.Frame{
		Nonce:      nonce,
		Epoch:      epoch,
		Ciphertext: ciphertext,
		Tag:        tag,
		Padding:    padding,
	}

	// Encode to wire format.
	wire, err := t.encoder.Encode(frame)
	if err != nil {
		return fmt.Errorf("transport: encoding frame: %w", err)
	}

	// Apply shaper delay.
	if t.shaper != nil {
		t.shaper.Delay()
	}

	// Send over UDP.
	t.peerMu.RLock()
	peer := t.peer
	t.peerMu.RUnlock()

	if peer == nil {
		return fmt.Errorf("transport: no peer address")
	}

	n, err := t.conn.WriteToUDP(wire, peer)
	if err != nil {
		return fmt.Errorf("transport: UDP write: %w", err)
	}
	if t.onSend != nil {
		t.onSend(n)
	}

	return nil
}

// Receive reads, deframes, decrypts, and returns a payload.
func (t *Tunnel) Receive() ([]byte, error) {
	buf := make([]byte, maxUDPSize)

	for {
		t.conn.SetReadDeadline(time.Now().Add(t.readTimeout))
		n, addr, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			// Timeout is not fatal — just retry.
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return nil, fmt.Errorf("transport: UDP read: %w", err)
		}

		// Decode frame.
		frame, err := t.decoder.Decode(buf[:n])
		if err != nil {
			if t.onDrop != nil {
				t.onDrop("decode", err)
			}
			continue
		}

		// Anti-replay check.
		if !t.replayCheck(frame.Epoch) {
			if t.onDrop != nil {
				t.onDrop("replay", fmt.Errorf("epoch %d rejected", frame.Epoch))
			}
			continue
		}

		// Reconstruct sealed data (ciphertext || tag).
		sealed := make([]byte, len(frame.Ciphertext)+len(frame.Tag))
		copy(sealed, frame.Ciphertext)
		copy(sealed[len(frame.Ciphertext):], frame.Tag)

		// Additional data.
		ad := epochBytes(frame.Epoch)

		// Decrypt.
		plaintext, err := t.aead.Open(nil, frame.Nonce, sealed, ad)
		if err != nil {
			if t.onDrop != nil {
				t.onDrop("aead", err)
			}
			continue
		}

		// Valid packet — update peer. If peer changed (reconnect from
		// different source port), reset the replay window.
		t.peerMu.Lock()
		if t.peer == nil {
			t.peer = addr
		} else if t.peer.String() != addr.String() {
			t.peer = addr
			t.replayMu.Lock()
			t.replayBmp = [replayWindowSize / 32]uint32{}
			t.replayMax = 0
			t.replayMu.Unlock()
		}
		t.peerMu.Unlock()

		// Commit replay window.
		t.replayCommit(frame.Epoch)

		if t.onRecv != nil {
			t.onRecv(n)
		}

		return plaintext, nil
	}
}

// Close closes the tunnel.
func (t *Tunnel) Close() error {
	return t.conn.Close()
}

// PeerAddr returns the current peer address.
func (t *Tunnel) PeerAddr() *net.UDPAddr {
	t.peerMu.RLock()
	defer t.peerMu.RUnlock()
	return t.peer
}

// --- Anti-replay ---

// replayCheck returns true if the epoch is acceptable (not replayed).
func (t *Tunnel) replayCheck(epoch uint32) bool {
	t.replayMu.Lock()
	defer t.replayMu.Unlock()

	if epoch == 0 {
		return false
	}

	// New epoch above current max — always accept.
	if epoch > t.replayMax {
		return true
	}

	// If epoch is far below replayMax, this is likely a new client session
	// with a different random starting epoch. Reset the window.
	diff := t.replayMax - epoch
	if diff >= replayWindowSize {
		// Reset — treat as a new session.
		t.replayBmp = [replayWindowSize / 32]uint32{}
		t.replayMax = 0
		return true
	}

	// Within window — check bitmap for duplicates.
	idx := epoch % replayWindowSize
	word := idx / 32
	bit := idx % 32
	if t.replayBmp[word]&(1<<bit) != 0 {
		return false // already seen
	}

	return true
}

// replayCommit marks an epoch as seen.
func (t *Tunnel) replayCommit(epoch uint32) {
	t.replayMu.Lock()
	defer t.replayMu.Unlock()

	if epoch > t.replayMax {
		// Advance window.
		shift := epoch - t.replayMax
		if shift >= replayWindowSize {
			// Clear entire window.
			t.replayBmp = [replayWindowSize / 32]uint32{}
		} else {
			// Shift bits. For simplicity, clear bits for positions that fell out.
			for i := t.replayMax + 1; i <= epoch; i++ {
				idx := i % replayWindowSize
				word := idx / 32
				bit := idx % 32
				t.replayBmp[word] &^= (1 << bit)
			}
		}
		t.replayMax = epoch
	}

	idx := epoch % replayWindowSize
	word := idx / 32
	bit := idx % 32
	t.replayBmp[word] |= (1 << bit)
}

// --- Helpers ---

func buildNonce(base []byte, epoch uint32, nonceSize int) []byte {
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

func epochBytes(epoch uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(epoch >> 24)
	b[1] = byte(epoch >> 16)
	b[2] = byte(epoch >> 8)
	b[3] = byte(epoch)
	return b
}

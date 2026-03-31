package mux

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultIdleTimeout is the default idle timeout for the tunnel.
	DefaultIdleTimeout = 5 * time.Minute
	// keepaliveInterval is how often to send keepalive if no traffic.
	keepaliveInterval = 30 * time.Second
)

// TransportConn is the interface the mux layer uses to send/receive raw bytes.
type TransportConn interface {
	Send(data []byte) error
	Receive() ([]byte, error)
	Close() error
}

// Session manages all multiplexed streams over one transport connection.
type Session struct {
	conn       TransportConn
	isClient   bool
	congestion CongestionController
	logger     *slog.Logger

	streams   map[uint32]*Stream
	streamsMu sync.RWMutex
	nextID    atomic.Uint32

	// acceptCh delivers streams opened by the remote peer.
	acceptCh chan *Stream

	ctx    context.Context
	cancel context.CancelFunc

	lastActivity atomic.Int64 // unix nanos
	idleTimeout  time.Duration

	closeOnce sync.Once
	done      chan struct{}
}

// NewSession creates a mux session over the given transport connection.
// isClient determines StreamID allocation: client uses odd IDs, server uses even.
func NewSession(conn TransportConn, isClient bool, logger *slog.Logger) *Session {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Session{
		conn:        conn,
		isClient:    isClient,
		congestion:  NewNewReno(),
		logger:      logger,
		streams:     make(map[uint32]*Stream),
		acceptCh:    make(chan *Stream, 64),
		ctx:         ctx,
		cancel:      cancel,
		idleTimeout: DefaultIdleTimeout,
		done:        make(chan struct{}),
	}

	if isClient {
		s.nextID.Store(1) // odd IDs
	} else {
		s.nextID.Store(2) // even IDs
	}

	s.touchActivity()
	go s.recvLoop()
	go s.keepaliveLoop()

	return s
}

// SetIdleTimeout configures the idle timeout.
func (s *Session) SetIdleTimeout(d time.Duration) {
	s.idleTimeout = d
}

// Open creates a new stream to the given destination (client side).
func (s *Session) Open(destAddr string, destPort uint16) (*Stream, error) {
	select {
	case <-s.done:
		return nil, fmt.Errorf("mux: session closed")
	default:
	}

	id := s.nextID.Add(2) - 2 // allocate and get the value before increment

	stream := newStream(id, s)
	stream.destAddr = destAddr
	stream.destPort = destPort

	s.streamsMu.Lock()
	s.streams[id] = stream
	s.streamsMu.Unlock()

	go stream.runRetransmitLoop()

	// Send OPEN command.
	cmd := &Command{
		Type:     CmdOpen,
		StreamID: id,
		DestAddr: destAddr,
		DestPort: destPort,
	}
	if err := s.sendCommand(cmd); err != nil {
		s.removeStream(id)
		return nil, fmt.Errorf("mux: sending OPEN: %w", err)
	}

	s.logger.Debug("stream opened", "stream_id", id, "dest", fmt.Sprintf("%s:%d", destAddr, destPort))
	return stream, nil
}

// Accept waits for and returns the next stream opened by the remote peer.
func (s *Session) Accept() (*Stream, error) {
	select {
	case stream := <-s.acceptCh:
		return stream, nil
	case <-s.done:
		return nil, fmt.Errorf("mux: session closed")
	}
}

// Close gracefully shuts down the session and all streams.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		close(s.done)

		// Close all streams.
		s.streamsMu.Lock()
		streams := make(map[uint32]*Stream, len(s.streams))
		for k, v := range s.streams {
			streams[k] = v
		}
		s.streamsMu.Unlock()

		for _, stream := range streams {
			stream.Close()
		}

		s.conn.Close()
	})
	return nil
}

// Done returns a channel that is closed when the session is shut down.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// sendCommand serializes and sends a command through the tunnel.
func (s *Session) sendCommand(cmd *Command) error {
	data, err := EncodeCommand(cmd)
	if err != nil {
		return err
	}
	s.touchActivity()
	return s.conn.Send(data)
}

// removeStream removes a stream from the registry.
func (s *Session) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
	s.logger.Debug("stream removed", "stream_id", id)
}

// getStream returns a stream by ID or nil if not found.
func (s *Session) getStream(id uint32) *Stream {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return s.streams[id]
}

// recvLoop reads commands from the transport and dispatches them.
func (s *Session) recvLoop() {
	defer func() {
		s.logger.Debug("recv loop exited")
		s.Close()
	}()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		data, err := s.conn.Receive()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				s.logger.Error("receive error", "err", err)
				return
			}
		}

		s.touchActivity()

		cmd, err := DecodeCommand(data)
		if err != nil {
			s.logger.Warn("decode error", "err", err)
			continue
		}

		s.dispatch(cmd)
	}
}

// dispatch routes a command to the appropriate handler.
func (s *Session) dispatch(cmd *Command) {
	switch cmd.Type {
	case CmdOpen:
		s.handleOpen(cmd)
	case CmdData:
		if stream := s.getStream(cmd.StreamID); stream != nil {
			stream.handleData(cmd)
		}
	case CmdAck:
		if stream := s.getStream(cmd.StreamID); stream != nil {
			stream.handleAck(cmd)
		}
	case CmdClose:
		if stream := s.getStream(cmd.StreamID); stream != nil {
			stream.handleClose()
		}
	}
}

// handleOpen processes an OPEN command from the remote peer.
func (s *Session) handleOpen(cmd *Command) {
	stream := newStream(cmd.StreamID, s)
	stream.destAddr = cmd.DestAddr
	stream.destPort = cmd.DestPort

	s.streamsMu.Lock()
	if _, exists := s.streams[cmd.StreamID]; exists {
		s.streamsMu.Unlock()
		s.logger.Warn("duplicate stream ID", "stream_id", cmd.StreamID)
		return
	}
	s.streams[cmd.StreamID] = stream
	s.streamsMu.Unlock()

	go stream.runRetransmitLoop()

	select {
	case s.acceptCh <- stream:
		s.logger.Debug("stream accepted", "stream_id", cmd.StreamID,
			"dest", fmt.Sprintf("%s:%d", cmd.DestAddr, cmd.DestPort))
	case <-s.done:
	}
}

// keepaliveLoop sends periodic keepalive and checks idle timeout.
func (s *Session) keepaliveLoop() {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			idle := time.Since(time.Unix(0, s.lastActivity.Load()))
			if idle >= s.idleTimeout {
				s.logger.Info("session idle timeout", "idle", idle)
				s.Close()
				return
			}
		}
	}
}

func (s *Session) touchActivity() {
	s.lastActivity.Store(time.Now().UnixNano())
}

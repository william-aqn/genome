package mux

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	errStreamClosed = errors.New("mux: stream closed")
	errStreamReset  = errors.New("mux: stream reset")
	errWindowFull   = errors.New("mux: send window full")
)

// streamState tracks the lifecycle of a stream.
type streamState int

const (
	stateOpen             streamState = iota
	stateHalfClosedLocal              // we sent CLOSE
	stateHalfClosedRemote             // peer sent CLOSE
	stateClosed
)

// Stream represents a single multiplexed bidirectional byte stream.
// It implements io.ReadWriteCloser.
type Stream struct {
	id      uint32
	state   streamState
	stateMu sync.RWMutex

	sendBuf *SendBuffer
	recvBuf *RecvBuffer
	flow    *FlowController
	rtt     *RTTEstimator

	// session is used to send commands through the tunnel.
	session *Session

	// destAddr/destPort are set for streams opened via OPEN command.
	destAddr string
	destPort uint16

	closeOnce sync.Once
	done      chan struct{}

	// dupAckCount tracks consecutive duplicate ACKs for fast retransmit.
	dupAckCount int
	lastAckSeq  uint32
}

func newStream(id uint32, sess *Session) *Stream {
	return &Stream{
		id:      id,
		state:   stateOpen,
		sendBuf: NewSendBuffer(),
		recvBuf: NewRecvBuffer(),
		flow:    NewFlowController(DefaultRecvWindow),
		rtt:     NewRTTEstimator(),
		session: sess,
		done:    make(chan struct{}),
	}
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// DestAddr returns the destination address (set for OPEN streams).
func (s *Stream) DestAddr() string { return s.destAddr }

// DestPort returns the destination port.
func (s *Stream) DestPort() uint16 { return s.destPort }

// Read reads data from the stream. Blocks until data is available or stream is closed.
func (s *Stream) Read(p []byte) (int, error) {
	s.stateMu.RLock()
	st := s.state
	s.stateMu.RUnlock()
	if st == stateClosed {
		return 0, errStreamClosed
	}
	n, err := s.recvBuf.Read(p)
	if n > 0 {
		s.flow.Release(uint32(n))
	}
	return n, err
}

// Write sends data on the stream. Segments into MSS-sized chunks.
// Uses per-stream flow control only; congestion control is advisory.
func (s *Stream) Write(p []byte) (int, error) {
	s.stateMu.RLock()
	st := s.state
	s.stateMu.RUnlock()
	if st == stateHalfClosedLocal || st == stateClosed {
		return 0, errStreamClosed
	}

	written := 0
	for written < len(p) {
		select {
		case <-s.done:
			return written, errStreamClosed
		default:
		}

		// Limit in-flight data to prevent UDP burst drops.
		// Allow up to 256 KB outstanding per stream before throttling.
		const maxOutstanding = 256 * 1024
		for s.sendBuf.Outstanding() > maxOutstanding {
			select {
			case <-s.done:
				return written, errStreamClosed
			case <-time.After(10 * time.Millisecond):
			}
		}

		chunk := p[written:]
		if len(chunk) > MSS {
			chunk = chunk[:MSS]
		}

		data := make([]byte, len(chunk))
		copy(data, chunk)

		seq := s.sendBuf.Append(data)

		cmd := &Command{
			Type:     CmdData,
			StreamID: s.id,
			Seq:      seq,
			Data:     data,
		}

		if err := s.session.sendCommand(cmd); err != nil {
			return written, fmt.Errorf("mux: write: %w", err)
		}

		written += len(chunk)
	}

	return written, nil
}

// Close initiates graceful close of the stream.
func (s *Stream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.stateMu.Lock()
		switch s.state {
		case stateOpen:
			s.state = stateHalfClosedLocal
		case stateHalfClosedRemote:
			s.state = stateClosed
		default:
			s.stateMu.Unlock()
			return
		}
		s.stateMu.Unlock()

		cmd := &Command{
			Type:     CmdClose,
			StreamID: s.id,
		}
		err = s.session.sendCommand(cmd)

		s.stateMu.RLock()
		st := s.state
		s.stateMu.RUnlock()
		if st == stateClosed {
			s.cleanup()
		}
	})
	return err
}

// handleData processes an incoming DATA command.
func (s *Stream) handleData(cmd *Command) {
	s.stateMu.RLock()
	st := s.state
	s.stateMu.RUnlock()
	if st == stateHalfClosedRemote || st == stateClosed {
		return
	}

	// Always accept data — don't drop on flow control violation.
	// Flow control is advisory via ACK window; dropping causes hangs
	// on large transfers when recv window depletes before Read drains.
	dataLen := uint32(len(cmd.Data))
	s.flow.Consume(dataLen) // best-effort tracking

	s.recvBuf.Insert(cmd.Seq, cmd.Data)
	s.sendAck()
}

// handleAck processes an incoming ACK command.
func (s *Stream) handleAck(cmd *Command) {
	// RTT sample (Karn's algorithm: only from non-retransmitted segments).
	if sample, ok := s.sendBuf.RTTSample(cmd.AckSeq); ok {
		s.rtt.Update(sample)
		s.session.congestion.OnAck(0, sample)
	}

	ackedBytes := s.sendBuf.AckTo(cmd.AckSeq)

	if len(cmd.SACKs) > 0 {
		ackedBytes += s.sendBuf.AckSACK(cmd.SACKs)
	}

	if ackedBytes > 0 {
		s.session.congestion.OnAck(ackedBytes, s.rtt.SRTT())
		s.dupAckCount = 0
		s.lastAckSeq = cmd.AckSeq
	} else if cmd.AckSeq == s.lastAckSeq {
		s.dupAckCount++
		if s.dupAckCount == 3 {
			s.session.congestion.OnLoss()
			if seg := s.sendBuf.GetUnacked(); seg != nil {
				s.retransmit(seg)
			}
		}
	}

	s.flow.UpdateSendWindow(cmd.Window)
}

// handleClose processes an incoming CLOSE command.
func (s *Stream) handleClose() {
	s.stateMu.Lock()
	switch s.state {
	case stateOpen:
		s.state = stateHalfClosedRemote
	case stateHalfClosedLocal:
		s.state = stateClosed
	default:
		s.stateMu.Unlock()
		return
	}
	st := s.state
	s.stateMu.Unlock()

	s.recvBuf.Close()

	if st == stateClosed {
		s.cleanup()
	}
}

// sendAck sends an ACK command with the current receive state.
func (s *Stream) sendAck() {
	nextSeq := s.recvBuf.NextExpected()
	sacks := s.recvBuf.SACKBlocks()
	window := s.flow.RecvWindow()

	cmd := &Command{
		Type:     CmdAck,
		StreamID: s.id,
		AckSeq:   nextSeq,
		SACKs:    sacks,
		Window:   window,
	}
	s.session.sendCommand(cmd)
}

// retransmit resends a segment.
func (s *Stream) retransmit(seg *Segment) {
	s.sendBuf.MarkRetransmitted(seg.Seq)
	cmd := &Command{
		Type:     CmdData,
		StreamID: s.id,
		Seq:      seg.Seq,
		Data:     seg.Data,
	}
	s.session.sendCommand(cmd)
}

// cleanup releases stream resources.
func (s *Stream) cleanup() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.session.removeStream(s.id)
}

// runRetransmitLoop periodically retransmits the oldest timed-out segment.
// Limited to one retransmit per tick to prevent congestion collapse.
// Also caps total sendBuf to prevent unbounded growth.
func (s *Stream) runRetransmitLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			// Trim acked segments from head to keep buffer bounded.
			s.sendBuf.TrimAcked()

			rto := s.rtt.RTO()
			seg := s.sendBuf.GetOldestRetransmittable(rto)
			if seg != nil && seg.Retransmits < 5 {
				s.retransmit(seg)
				s.rtt.BackoffRTO()
			}
		}
	}
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

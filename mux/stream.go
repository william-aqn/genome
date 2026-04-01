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
)

// streamState tracks the lifecycle of a stream.
type streamState int

const (
	stateOpen             streamState = iota
	stateHalfClosedLocal              // we sent CLOSE
	stateHalfClosedRemote             // peer sent CLOSE
	stateClosed
)

// maxOutstanding limits in-flight bytes per stream to prevent
// UDP burst drops. Write blocks (via Cond) when outstanding exceeds this.
// Set to 256 KB — enough for high throughput without overwhelming UDP.
// At 1200 MSS this is ~213 packets in flight.
const maxOutstanding uint32 = 256 * 1024

// Stream represents a single multiplexed bidirectional byte stream.
// Implements io.ReadWriteCloser.
type Stream struct {
	id      uint32
	state   streamState
	stateMu sync.RWMutex

	sendBuf *SendBuffer
	recvBuf *RecvBuffer
	flow    *FlowController
	rtt     *RTTEstimator

	session *Session

	destAddr string
	destPort uint16

	closeOnce sync.Once
	done      chan struct{}

	// Fast retransmit state.
	dupAckCount int
	lastAckSeq  uint32

	// Delayed ACK counter.
	unackedCount int
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

// DestAddr returns the destination address.
func (s *Stream) DestAddr() string { return s.destAddr }

// DestPort returns the destination port.
func (s *Stream) DestPort() uint16 { return s.destPort }

// Read reads data from the stream. Blocks until data is available.
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
// Blocks when in-flight data exceeds maxOutstanding (256 KB) to prevent
// UDP burst packet loss. Unblocked by AckTo/AckSACK via sendBuf.cond.
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

		// Throttle: limit outstanding to prevent UDP burst drops.
		if s.sendBuf.Outstanding() >= maxOutstanding {
			s.sendBuf.WaitOutstandingBelowTimeout(maxOutstanding, 20*time.Millisecond)
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
// Sends ACK every ackInterval packets to avoid flooding the return channel.
func (s *Stream) handleData(cmd *Command) {
	s.stateMu.RLock()
	st := s.state
	s.stateMu.RUnlock()
	if st == stateHalfClosedRemote || st == stateClosed {
		return
	}

	s.flow.Consume(uint32(len(cmd.Data)))
	s.recvBuf.Insert(cmd.Seq, cmd.Data)

	// Delayed ACK: send every 32 packets or when recv window is low.
	s.unackedCount++
	if s.unackedCount >= 32 || s.flow.RecvWindow() < DefaultRecvWindow/4 {
		s.sendAck()
		s.unackedCount = 0
	}
}

// handleAck processes an incoming ACK command.
func (s *Stream) handleAck(cmd *Command) {
	// RTT sample (Karn's algorithm).
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

// sendAck sends an ACK with the current receive state.
func (s *Stream) sendAck() {
	cmd := &Command{
		Type:     CmdAck,
		StreamID: s.id,
		AckSeq:   s.recvBuf.NextExpected(),
		SACKs:    s.recvBuf.SACKBlocks(),
		Window:   s.flow.RecvWindow(),
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

// cleanup releases stream resources and unblocks pending Write calls.
func (s *Stream) cleanup() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	// Wake any Write blocked in WaitOutstandingBelow.
	s.sendBuf.WakeAll()
	s.session.removeStream(s.id)
}

// runRetransmitLoop retransmits the oldest timed-out segment periodically
// and flushes pending delayed ACKs.
func (s *Stream) runRetransmitLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.sendBuf.TrimAcked()

			// Flush delayed ACK if any data received.
			if s.unackedCount > 0 {
				s.sendAck()
				s.unackedCount = 0
			}

			rto := s.rtt.RTO()
			seg := s.sendBuf.GetOldestRetransmittable(rto)
			if seg != nil && seg.Retransmits < 5 {
				s.retransmit(seg)
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

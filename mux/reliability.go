package mux

import (
	"sync"
	"time"
)

const (
	minRTO         = 200 * time.Millisecond
	maxRTO         = 60 * time.Second
	initialRTO     = 1 * time.Second
	maxRetransmits = 10
)

// RTTEstimator tracks smoothed RTT using the Jacobson/Karels algorithm.
type RTTEstimator struct {
	mu        sync.Mutex
	srtt      time.Duration // smoothed RTT
	rttvar    time.Duration // RTT variance
	rto       time.Duration // retransmission timeout
	hasSample bool
}

// NewRTTEstimator creates an estimator with initial RTO.
func NewRTTEstimator() *RTTEstimator {
	return &RTTEstimator{
		rto: initialRTO,
	}
}

// Update processes a new RTT sample.
func (e *RTTEstimator) Update(sample time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.hasSample {
		e.srtt = sample
		e.rttvar = sample / 2
		e.hasSample = true
	} else {
		// SRTT = 7/8 * SRTT + 1/8 * sample
		diff := e.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		e.rttvar = (3*e.rttvar + diff) / 4
		e.srtt = (7*e.srtt + sample) / 8
	}

	e.rto = e.srtt + 4*e.rttvar
	if e.rto < minRTO {
		e.rto = minRTO
	}
	if e.rto > maxRTO {
		e.rto = maxRTO
	}
}

// RTO returns the current retransmission timeout.
func (e *RTTEstimator) RTO() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rto
}

// SRTT returns the smoothed RTT.
func (e *RTTEstimator) SRTT() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.srtt
}

// BackoffRTO doubles the RTO (exponential backoff on timeout).
func (e *RTTEstimator) BackoffRTO() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rto *= 2
	if e.rto > maxRTO {
		e.rto = maxRTO
	}
}

// --- Send buffer ---

// Segment is a sent-but-unacked data segment.
type Segment struct {
	Seq         uint32
	Data        []byte
	SentAt      time.Time
	Retransmits int
	Acked       bool
}

// SendBuffer manages outgoing unacknowledged segments.
type SendBuffer struct {
	mu          sync.Mutex
	segments    []*Segment
	nextSeq     uint32
	outstanding uint32 // cached bytes in-flight
}

// NewSendBuffer creates an empty send buffer starting at seq 0.
func NewSendBuffer() *SendBuffer {
	return &SendBuffer{}
}

// Append adds a new segment to the send buffer and returns the assigned seq.
func (sb *SendBuffer) Append(data []byte) uint32 {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	seq := sb.nextSeq
	sb.segments = append(sb.segments, &Segment{
		Seq:    seq,
		Data:   data,
		SentAt: time.Now(),
	})
	sb.nextSeq = seq + uint32(len(data))
	sb.outstanding += uint32(len(data))
	return seq
}

// NextSeq returns the next sequence number to use.
func (sb *SendBuffer) NextSeq() uint32 {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.nextSeq
}

// AckTo marks all segments with seq < ackSeq as acknowledged
// and removes them from the buffer. Returns total bytes acked.
func (sb *SendBuffer) AckTo(ackSeq uint32) uint32 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	var ackedBytes uint32
	cutoff := 0
	for i, seg := range sb.segments {
		segEnd := seg.Seq + uint32(len(seg.Data))
		if segEnd <= ackSeq {
			if !seg.Acked {
				n := uint32(len(seg.Data))
				ackedBytes += n
				sb.outstanding -= n
				seg.Acked = true
			}
			cutoff = i + 1
		} else {
			break
		}
	}
	if cutoff > 0 {
		sb.segments = sb.segments[cutoff:]
	}
	return ackedBytes
}

// AckSACK marks segments within SACK ranges as acknowledged.
// Returns total bytes acked by SACK blocks.
func (sb *SendBuffer) AckSACK(sacks []SACKBlock) uint32 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	var ackedBytes uint32
	for _, blk := range sacks {
		for _, seg := range sb.segments {
			segEnd := seg.Seq + uint32(len(seg.Data))
			if seg.Seq >= blk.Left && segEnd <= blk.Right && !seg.Acked {
				seg.Acked = true
				n := uint32(len(seg.Data))
				ackedBytes += n
				sb.outstanding -= n
			}
		}
	}
	return ackedBytes
}

// GetUnacked returns the first unacked segment for retransmission.
// Returns nil if all segments are acked.
func (sb *SendBuffer) GetUnacked() *Segment {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for _, seg := range sb.segments {
		if !seg.Acked {
			return seg
		}
	}
	return nil
}

// GetRetransmittable returns segments that need retransmission
// (unacked and either timed out or explicitly requested).
func (sb *SendBuffer) GetRetransmittable(rto time.Duration) []*Segment {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	now := time.Now()
	var result []*Segment
	for _, seg := range sb.segments {
		if !seg.Acked && now.Sub(seg.SentAt) >= rto && seg.Retransmits < maxRetransmits {
			result = append(result, seg)
		}
	}
	return result
}

// GetOldestRetransmittable returns the single oldest unacked segment
// that has exceeded the RTO, or nil.
func (sb *SendBuffer) GetOldestRetransmittable(rto time.Duration) *Segment {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	now := time.Now()
	for _, seg := range sb.segments {
		if !seg.Acked && now.Sub(seg.SentAt) >= rto && seg.Retransmits < maxRetransmits {
			return seg
		}
	}
	return nil
}

// MarkRetransmitted updates the sent time and retransmit count.
func (sb *SendBuffer) MarkRetransmitted(seq uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for _, seg := range sb.segments {
		if seg.Seq == seq {
			seg.SentAt = time.Now()
			seg.Retransmits++
			return
		}
	}
}

// TrimAcked removes fully acked segments from the head of the buffer.
func (sb *SendBuffer) TrimAcked() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	cutoff := 0
	for i, seg := range sb.segments {
		if seg.Acked {
			cutoff = i + 1
		} else {
			break
		}
	}
	if cutoff > 0 {
		sb.segments = sb.segments[cutoff:]
	}
}

// Outstanding returns the total bytes in-flight (sent but unacked). O(1).
func (sb *SendBuffer) Outstanding() uint32 {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.outstanding
}

// RTTSample returns a valid RTT sample from the most recently acked segment,
// if the segment was not retransmitted (Karn's algorithm).
func (sb *SendBuffer) RTTSample(ackSeq uint32) (time.Duration, bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for _, seg := range sb.segments {
		segEnd := seg.Seq + uint32(len(seg.Data))
		if segEnd <= ackSeq && seg.Retransmits == 0 && !seg.Acked {
			return time.Since(seg.SentAt), true
		}
	}
	return 0, false
}

// --- Receive buffer ---

// recvSegment is an out-of-order received segment.
type recvSegment struct {
	seq  uint32
	data []byte
}

// RecvBuffer reorders incoming data segments.
type RecvBuffer struct {
	mu        sync.Mutex
	nextSeq   uint32        // next expected sequence number
	segments  []recvSegment // out-of-order segments, sorted by seq
	ready     []byte        // contiguous data ready to read
	readyCond *sync.Cond
	closed    bool
}

// NewRecvBuffer creates a receive buffer starting at seq 0.
func NewRecvBuffer() *RecvBuffer {
	rb := &RecvBuffer{}
	rb.readyCond = sync.NewCond(&rb.mu)
	return rb
}

// Insert adds a received segment. Handles duplicates and out-of-order delivery.
// Returns true if new data was accepted.
func (rb *RecvBuffer) Insert(seq uint32, data []byte) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.closed {
		return false
	}

	segEnd := seq + uint32(len(data))

	// Already received.
	if segEnd <= rb.nextSeq {
		return false
	}

	// Trim overlap with already-received data.
	if seq < rb.nextSeq {
		trim := rb.nextSeq - seq
		data = data[trim:]
		seq = rb.nextSeq
	}

	// Check for duplicates in out-of-order buffer.
	for _, s := range rb.segments {
		if s.seq == seq {
			return false
		}
	}

	// Insert sorted by seq.
	inserted := false
	for i, s := range rb.segments {
		if seq < s.seq {
			rb.segments = append(rb.segments, recvSegment{})
			copy(rb.segments[i+1:], rb.segments[i:])
			rb.segments[i] = recvSegment{seq: seq, data: append([]byte(nil), data...)}
			inserted = true
			break
		}
	}
	if !inserted {
		rb.segments = append(rb.segments, recvSegment{seq: seq, data: append([]byte(nil), data...)})
	}

	// Drain contiguous segments.
	rb.drainContiguous()

	return true
}

// drainContiguous moves contiguous data from segments to the ready buffer.
// Must be called with mu held.
func (rb *RecvBuffer) drainContiguous() {
	for len(rb.segments) > 0 && rb.segments[0].seq == rb.nextSeq {
		seg := rb.segments[0]
		rb.ready = append(rb.ready, seg.data...)
		rb.nextSeq += uint32(len(seg.data))
		rb.segments = rb.segments[1:]
		rb.readyCond.Signal()
	}
}

// Read reads contiguous data from the buffer. Blocks if no data is available.
func (rb *RecvBuffer) Read(p []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for len(rb.ready) == 0 {
		if rb.closed {
			return 0, errStreamClosed
		}
		rb.readyCond.Wait()
	}

	n := copy(p, rb.ready)
	rb.ready = rb.ready[n:]
	return n, nil
}

// ReadyLen returns the number of contiguous bytes available to read.
func (rb *RecvBuffer) ReadyLen() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return len(rb.ready)
}

// NextExpected returns the next expected sequence number (cumulative ACK value).
func (rb *RecvBuffer) NextExpected() uint32 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.nextSeq
}

// SACKBlocks returns the SACK blocks for out-of-order data.
func (rb *RecvBuffer) SACKBlocks() []SACKBlock {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.segments) == 0 {
		return nil
	}

	var blocks []SACKBlock
	start := rb.segments[0].seq
	end := start + uint32(len(rb.segments[0].data))

	for i := 1; i < len(rb.segments); i++ {
		seg := rb.segments[i]
		if seg.seq == end {
			end = seg.seq + uint32(len(seg.data))
		} else {
			blocks = append(blocks, SACKBlock{Left: start, Right: end})
			start = seg.seq
			end = seg.seq + uint32(len(seg.data))
		}
	}
	blocks = append(blocks, SACKBlock{Left: start, Right: end})
	return blocks
}

// Close marks the buffer as closed, waking any blocked readers.
func (rb *RecvBuffer) Close() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.closed = true
	rb.readyCond.Broadcast()
}

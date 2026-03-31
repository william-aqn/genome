package mux

import (
	"bytes"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// --- Command tests ---

func TestCommandRoundTrip(t *testing.T) {
	cmds := []*Command{
		{Type: CmdOpen, StreamID: 1, DestAddr: "example.com", DestPort: 443},
		{Type: CmdData, StreamID: 3, Seq: 100, Data: []byte("hello world")},
		{Type: CmdClose, StreamID: 5},
		{Type: CmdAck, StreamID: 7, AckSeq: 200, Window: 65536,
			SACKs: []SACKBlock{{Left: 300, Right: 400}, {Left: 500, Right: 600}}},
		{Type: CmdData, StreamID: 9, Seq: 0, Data: []byte{}},
		{Type: CmdOpen, StreamID: 11, DestAddr: "192.168.1.1", DestPort: 80},
	}

	for i, orig := range cmds {
		data, err := EncodeCommand(orig)
		if err != nil {
			t.Fatalf("cmd %d: encode error: %v", i, err)
		}
		decoded, err := DecodeCommand(data)
		if err != nil {
			t.Fatalf("cmd %d: decode error: %v", i, err)
		}
		if decoded.Type != orig.Type || decoded.StreamID != orig.StreamID {
			t.Fatalf("cmd %d: type/id mismatch", i)
		}
		switch orig.Type {
		case CmdOpen:
			if decoded.DestAddr != orig.DestAddr || decoded.DestPort != orig.DestPort {
				t.Fatalf("cmd %d: OPEN dest mismatch", i)
			}
		case CmdData:
			if decoded.Seq != orig.Seq || !bytes.Equal(decoded.Data, orig.Data) {
				t.Fatalf("cmd %d: DATA mismatch", i)
			}
		case CmdAck:
			if decoded.AckSeq != orig.AckSeq || decoded.Window != orig.Window {
				t.Fatalf("cmd %d: ACK values mismatch", i)
			}
			if len(decoded.SACKs) != len(orig.SACKs) {
				t.Fatalf("cmd %d: SACK count mismatch", i)
			}
			for j := range orig.SACKs {
				if decoded.SACKs[j] != orig.SACKs[j] {
					t.Fatalf("cmd %d: SACK block %d mismatch", i, j)
				}
			}
		}
	}
}

// --- RecvBuffer tests ---

func TestRecvBufferInOrder(t *testing.T) {
	rb := NewRecvBuffer()
	rb.Insert(0, []byte("hello"))
	rb.Insert(5, []byte(" world"))

	buf := make([]byte, 20)
	n, err := rb.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "hello world")
	}
}

func TestRecvBufferOutOfOrder(t *testing.T) {
	rb := NewRecvBuffer()
	rb.Insert(5, []byte(" world"))
	rb.Insert(0, []byte("hello"))

	buf := make([]byte, 20)
	n, err := rb.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("got %q", string(buf[:n]))
	}
}

func TestRecvBufferDuplicate(t *testing.T) {
	rb := NewRecvBuffer()
	rb.Insert(0, []byte("hello"))
	ok := rb.Insert(0, []byte("hello")) // duplicate
	if ok {
		t.Fatal("expected duplicate to be rejected")
	}
}

func TestRecvBufferSACK(t *testing.T) {
	rb := NewRecvBuffer()
	rb.Insert(10, []byte("bbb")) // out of order
	rb.Insert(20, []byte("ccc")) // out of order

	sacks := rb.SACKBlocks()
	if len(sacks) != 2 {
		t.Fatalf("expected 2 SACK blocks, got %d", len(sacks))
	}
	if sacks[0].Left != 10 || sacks[0].Right != 13 {
		t.Fatalf("SACK[0] = %+v", sacks[0])
	}
	if sacks[1].Left != 20 || sacks[1].Right != 23 {
		t.Fatalf("SACK[1] = %+v", sacks[1])
	}
}

// --- SendBuffer tests ---

func TestSendBufferAppendAndAck(t *testing.T) {
	sb := NewSendBuffer()
	sb.Append([]byte("aaaa")) // seq 0, len 4
	sb.Append([]byte("bbbb")) // seq 4, len 4

	if sb.Outstanding() != 8 {
		t.Fatalf("outstanding = %d, want 8", sb.Outstanding())
	}

	acked := sb.AckTo(4) // ack first segment
	if acked != 4 {
		t.Fatalf("acked = %d, want 4", acked)
	}
	if sb.Outstanding() != 4 {
		t.Fatalf("outstanding after ack = %d, want 4", sb.Outstanding())
	}
}

func TestSendBufferSACK(t *testing.T) {
	sb := NewSendBuffer()
	sb.Append([]byte("aaa")) // seq 0
	sb.Append([]byte("bbb")) // seq 3
	sb.Append([]byte("ccc")) // seq 6

	// SACK the third segment (seq 6-9) but not the second.
	sacked := sb.AckSACK([]SACKBlock{{Left: 6, Right: 9}})
	if sacked != 3 {
		t.Fatalf("sacked = %d, want 3", sacked)
	}

	// First unacked should be seq 0.
	seg := sb.GetUnacked()
	if seg == nil || seg.Seq != 0 {
		t.Fatalf("first unacked = %+v, want seq 0", seg)
	}
}

// --- RTT Estimator tests ---

func TestRTTEstimator(t *testing.T) {
	e := NewRTTEstimator()
	if e.RTO() != initialRTO {
		t.Fatalf("initial RTO = %v, want %v", e.RTO(), initialRTO)
	}

	e.Update(100 * time.Millisecond)
	if e.SRTT() != 100*time.Millisecond {
		t.Fatalf("SRTT after first sample = %v, want 100ms", e.SRTT())
	}

	// Second sample — smoothing.
	e.Update(200 * time.Millisecond)
	srtt := e.SRTT()
	if srtt < 100*time.Millisecond || srtt > 200*time.Millisecond {
		t.Fatalf("SRTT after second sample = %v, expected between 100ms and 200ms", srtt)
	}

	e.BackoffRTO()
	rto := e.RTO()
	if rto < 200*time.Millisecond {
		t.Fatalf("backed-off RTO = %v, expected >= 200ms", rto)
	}
}

// --- NewReno tests ---

func TestNewRenoSlowStart(t *testing.T) {
	nr := NewNewReno()
	initial := nr.SendWindow()

	nr.OnAck(MSS, 50*time.Millisecond)
	after := nr.SendWindow()
	if after <= initial {
		t.Fatalf("cwnd did not increase in slow start: %d -> %d", initial, after)
	}
}

func TestNewRenoOnLoss(t *testing.T) {
	nr := NewNewReno()
	// Grow cwnd.
	for i := 0; i < 10; i++ {
		nr.OnAck(MSS, 50*time.Millisecond)
	}
	before := nr.SendWindow()
	nr.OnLoss()
	after := nr.SendWindow()
	if after >= before {
		t.Fatalf("cwnd did not decrease on loss: %d -> %d", before, after)
	}
}

func TestNewRenoOnTimeout(t *testing.T) {
	nr := NewNewReno()
	for i := 0; i < 10; i++ {
		nr.OnAck(MSS, 50*time.Millisecond)
	}
	nr.OnTimeout()
	if nr.SendWindow() != minCWND {
		t.Fatalf("cwnd after timeout = %d, want %d", nr.SendWindow(), minCWND)
	}
}

// --- Flow control tests ---

func TestFlowControl(t *testing.T) {
	fc := NewFlowController(1000)

	if !fc.Consume(600) {
		t.Fatal("consume 600 should succeed")
	}
	if fc.RecvWindow() != 400 {
		t.Fatalf("recv window = %d, want 400", fc.RecvWindow())
	}

	if fc.Consume(500) {
		t.Fatal("consume 500 should fail (only 400 available)")
	}

	win := fc.Release(600)
	if win != 1000 {
		t.Fatalf("after release, window = %d, want 1000", win)
	}
}

// --- Session integration test with mock transport ---

type mockTransport struct {
	mu     sync.Mutex
	sendCh chan []byte
	recvCh chan []byte
	closed bool
}

func newMockTransportPair() (*mockTransport, *mockTransport) {
	ch1 := make(chan []byte, 256)
	ch2 := make(chan []byte, 256)
	return &mockTransport{sendCh: ch1, recvCh: ch2},
		&mockTransport{sendCh: ch2, recvCh: ch1}
}

func (m *mockTransport) Send(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return io.ErrClosedPipe
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case m.sendCh <- buf:
		return nil
	default:
		return io.ErrClosedPipe
	}
}

func (m *mockTransport) Receive() ([]byte, error) {
	data, ok := <-m.recvCh
	if !ok {
		return nil, io.EOF
	}
	return data, nil
}

func (m *mockTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.sendCh)
	}
	return nil
}

func TestSessionOpenAccept(t *testing.T) {
	clientConn, serverConn := newMockTransportPair()
	logger := slog.Default()

	clientSess := NewSession(clientConn, true, logger)
	serverSess := NewSession(serverConn, false, logger)
	defer clientSess.Close()
	defer serverSess.Close()

	// Client opens a stream.
	clientStream, err := clientSess.Open("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}

	// Server accepts the stream.
	serverStream, err := serverSess.Accept()
	if err != nil {
		t.Fatal(err)
	}

	if serverStream.DestAddr() != "example.com" || serverStream.DestPort() != 443 {
		t.Fatalf("server stream dest = %s:%d, want example.com:443",
			serverStream.DestAddr(), serverStream.DestPort())
	}

	// Bidirectional data exchange.
	testData := []byte("hello from client")
	go func() {
		clientStream.Write(testData)
	}()

	// Server reads.
	buf := make([]byte, 100)
	n, err := serverStream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("server received %q, want %q", buf[:n], testData)
	}

	// Server responds.
	responseData := []byte("hello from server")
	go func() {
		serverStream.Write(responseData)
	}()

	n, err = clientStream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], responseData) {
		t.Fatalf("client received %q, want %q", buf[:n], responseData)
	}
}

func TestSessionMultipleStreams(t *testing.T) {
	clientConn, serverConn := newMockTransportPair()
	logger := slog.Default()

	clientSess := NewSession(clientConn, true, logger)
	serverSess := NewSession(serverConn, false, logger)
	defer clientSess.Close()
	defer serverSess.Close()

	const numStreams = 5
	var wg sync.WaitGroup

	// Client opens streams.
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			stream, err := clientSess.Open("host", uint16(8000+idx))
			if err != nil {
				t.Errorf("open stream %d: %v", idx, err)
				return
			}
			msg := []byte("stream data")
			stream.Write(msg)
		}(i)
	}

	// Server accepts and reads.
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := serverSess.Accept()
			if err != nil {
				t.Errorf("accept: %v", err)
				return
			}
			buf := make([]byte, 100)
			n, err := stream.Read(buf)
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if string(buf[:n]) != "stream data" {
				t.Errorf("got %q", buf[:n])
			}
		}()
	}

	wg.Wait()
}

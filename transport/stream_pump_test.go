package transport

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

// --- buildWagon / parseWagon unit tests ---

func TestBuildWagonChaff(t *testing.T) {
	w, err := buildWagon(nil, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 200 {
		t.Fatalf("wagon size: got %d want 200", len(w))
	}
	got, isReal, err := parseWagon(w)
	if err != nil {
		t.Fatal(err)
	}
	if isReal || got != nil {
		t.Fatalf("expected chaff, got real=%v payload=%v", isReal, got)
	}
}

func TestBuildWagonPartial(t *testing.T) {
	real := []byte("hello stream mode")
	w, err := buildWagon(real, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 200 {
		t.Fatalf("wagon size: got %d want 200", len(w))
	}
	got, isReal, err := parseWagon(w)
	if err != nil {
		t.Fatal(err)
	}
	if !isReal || !bytes.Equal(got, real) {
		t.Fatalf("got real=%v payload=%q want %q", isReal, got, real)
	}
}

func TestBuildWagonFullyPacked(t *testing.T) {
	real := bytes.Repeat([]byte{0xAA}, 198) // exactly size-2
	w, err := buildWagon(real, 200)
	if err != nil {
		t.Fatal(err)
	}
	got, isReal, err := parseWagon(w)
	if err != nil {
		t.Fatal(err)
	}
	if !isReal || !bytes.Equal(got, real) {
		t.Fatal("full-wagon roundtrip mismatch")
	}
}

func TestBuildWagonOverflow(t *testing.T) {
	real := make([]byte, 199) // one byte too many for size-2=198
	if _, err := buildWagon(real, 200); err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestParseWagonShort(t *testing.T) {
	if _, _, err := parseWagon([]byte{0x00}); err == nil {
		t.Fatal("expected error on 1-byte wagon")
	}
}

func TestParseWagonBadLen(t *testing.T) {
	// RealLen=100 but only 10 bytes total — malformed.
	w := []byte{0, 100, 1, 2, 3, 4, 5, 6, 7, 8}
	if _, _, err := parseWagon(w); err == nil {
		t.Fatal("expected overflow error")
	}
}

// --- Pump integration tests over a loopback UDP pair ---

// drainReceiver repeatedly calls Receive on tun and discards results. Exits
// when Receive returns an error (typically from conn.Close).
func drainReceiver(tun *Tunnel) {
	for {
		if _, err := tun.Receive(); err != nil {
			return
		}
	}
}

func TestStreamPumpEmitsWithinEnvelope(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)
	defer tun2.Close()

	// Tight envelope so we can measure.
	min, max := 60_000, 120_000
	pump, err := NewStreamPump(tun1, min, max)
	if err != nil {
		t.Fatal(err)
	}

	var wireBytes atomic.Int64
	tun1.SetStatsCallbacks(func(n int) { wireBytes.Add(int64(n)) }, nil)

	tun1.AttachPump(pump)
	defer tun1.Close()

	go drainReceiver(tun2)

	measureStart := time.Now()
	time.Sleep(2 * time.Second)
	elapsed := time.Since(measureStart)

	observed := float64(wireBytes.Load()) / elapsed.Seconds()
	t.Logf("observed wire rate: %.0f bytes/sec (plaintext envelope %d..%d)", observed, min, max)

	// Wire bytes include morph header + AEAD tag per packet, so observed
	// wire rate > plaintext rate by ~100 bytes × packet-rate. For this
	// envelope that's ≲15 KB/s of overhead. Assert within generous bands.
	if observed < float64(min)*0.7 {
		t.Fatalf("rate too low: %.0f < %d*0.7", observed, min)
	}
	if observed > float64(max)*2.0 {
		t.Fatalf("rate too high: %.0f > %d*2.0", observed, max)
	}
}

func TestStreamPumpBurstOnOverload(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)
	defer tun2.Close()

	// Low envelope so a small flood forces burst.
	min, max := 5_000, 10_000
	pump, err := NewStreamPump(tun1, min, max)
	if err != nil {
		t.Fatal(err)
	}

	var burstTicks atomic.Int64
	pump.SetBurstCallback(func() { burstTicks.Add(1) })

	tun1.AttachPump(pump)
	defer tun1.Close()

	go drainReceiver(tun2)

	// Flood the queue. Payload size < WagonMin-2 so Enqueue accepts.
	payload := make([]byte, 256)
	flood := make(chan struct{})
	go func() {
		defer close(flood)
		for i := 0; i < 4096; i++ {
			if err := pump.Enqueue(payload); err != nil {
				return
			}
		}
	}()

	// Let burst mode engage.
	time.Sleep(1 * time.Second)

	if burstTicks.Load() == 0 {
		t.Fatalf("expected burst ticks under overload, got 0")
	}
	t.Logf("burst ticks in 1s: %d", burstTicks.Load())
}

func TestStreamPumpShutdown(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)
	defer tun2.Close()

	pump, err := NewStreamPump(tun1, 10_000, 20_000)
	if err != nil {
		t.Fatal(err)
	}
	tun1.AttachPump(pump)

	go drainReceiver(tun2)

	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		tun1.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel Close did not return within 2s (pump likely hung)")
	}

	if err := pump.Enqueue([]byte("late")); err == nil {
		t.Fatal("Enqueue after Close should return ErrPumpClosed")
	}
}

func TestTunnelStreamModeRoundtrip(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)

	// Both sides get a pump so the receiver knows to strip wagon prefix.
	p1, err := NewStreamPump(tun1, 50_000, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := NewStreamPump(tun2, 50_000, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	tun1.AttachPump(p1)
	tun2.AttachPump(p2)
	defer tun1.Close()
	defer tun2.Close()

	// Enqueue one real payload on tun1. Pump fills the rest with chaff.
	want := []byte("real payload through a stream of wagons")
	if err := tun1.Send(want); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Receive loop on tun2 skips chaff silently; eventually returns the real bytes.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tun2.SetReadTimeout(500 * time.Millisecond)
		got, err := tun2.Receive()
		if err != nil {
			continue
		}
		if bytes.Equal(got, want) {
			return
		}
		t.Fatalf("unexpected payload: got %q want %q", got, want)
	}
	t.Fatal("timed out waiting for real payload through the stream")
}

func TestTunnelReceiveRejectsMalformedWagon(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)

	// Only tun2 has a pump — tun1 will bypass it by calling sendRaw directly.
	pump, err := NewStreamPump(tun2, 10_000, 20_000)
	if err != nil {
		t.Fatal(err)
	}
	tun2.AttachPump(pump)
	defer tun1.Close()
	defer tun2.Close()

	var drops atomic.Int64
	tun2.SetDropCallback(func(reason string, err error) {
		if reason == "wagon" {
			drops.Add(1)
		}
	})

	// Send a plaintext that's too short to be a valid wagon.
	if err := tun1.sendRaw([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	// Receive with a short timeout — should observe a drop and then time out.
	tun2.SetReadTimeout(500 * time.Millisecond)
	_ = tun2.Receive // we don't assert the return value; just let one iter run
	go func() {
		_, _ = tun2.Receive()
	}()
	time.Sleep(600 * time.Millisecond)

	if drops.Load() == 0 {
		t.Fatal("expected wagon drop callback on malformed plaintext")
	}
}

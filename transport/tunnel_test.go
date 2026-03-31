package transport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"genome/crypto"
	"genome/morph"
)

func setupLoopbackTunnels(t *testing.T) (*Tunnel, *Tunnel) {
	t.Helper()

	psk := []byte("test-psk-for-transport-layer-32!!")
	keys, err := crypto.DeriveSessionKeys(psk, nil, crypto.CipherChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}

	genome := morph.Derive(keys.GenomeSeed)

	// Determine which AEAD constructor to use based on nonce size.
	var aead1, aead2 interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	_ = aead1
	_ = aead2

	var aeadNew func([]byte) (interface{}, error)
	_ = aeadNew

	// Create appropriate AEAD for the genome's nonce size.
	var cAead1, cAead2 interface{}
	_ = cAead1
	_ = cAead2

	aead, err := newAEADForGenome(keys.AEADKey, keys.Suite, genome)
	if err != nil {
		t.Fatal(err)
	}

	aead2Copy, err := newAEADForGenome(keys.AEADKey, keys.Suite, genome)
	if err != nil {
		t.Fatal(err)
	}

	// Create two UDP sockets on loopback.
	addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn1, err := net.ListenUDP("udp", addr1)
	if err != nil {
		t.Fatal(err)
	}

	addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := net.ListenUDP("udp", addr2)
	if err != nil {
		t.Fatal(err)
	}

	shaper := NewShaper(0, 0) // no jitter for tests

	tun1 := NewTunnel(conn1, conn2.LocalAddr().(*net.UDPAddr), aead, keys.NonceBase, genome, shaper)
	tun2 := NewTunnel(conn2, conn1.LocalAddr().(*net.UDPAddr), aead2Copy, keys.NonceBase, genome, shaper)

	tun1.SetReadTimeout(5 * time.Second)
	tun2.SetReadTimeout(5 * time.Second)

	return tun1, tun2
}

func newAEADForGenome(key []byte, suite crypto.CipherSuite, g *morph.Genome) (interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	NonceSize() int
	Overhead() int
}, error) {
	if g.NonceSize == 24 {
		return crypto.NewXAEAD(key)
	}
	return crypto.NewAEAD(key, suite)
}

func TestTunnelRoundTrip(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)
	defer tun1.Close()
	defer tun2.Close()

	testData := []byte("hello through the polymorphic tunnel!")

	// tun1 sends to tun2.
	if err := tun1.Send(testData); err != nil {
		t.Fatal(err)
	}

	received, err := tun2.Receive()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(received, testData) {
		t.Fatalf("received %q, want %q", received, testData)
	}
}

func TestTunnelBidirectional(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)
	defer tun1.Close()
	defer tun2.Close()

	// tun1 → tun2
	msg1 := []byte("from tunnel 1")
	tun1.Send(msg1)
	got, _ := tun2.Receive()
	if !bytes.Equal(got, msg1) {
		t.Fatalf("tun2 got %q, want %q", got, msg1)
	}

	// tun2 → tun1
	msg2 := []byte("from tunnel 2")
	tun2.Send(msg2)
	got, _ = tun1.Receive()
	if !bytes.Equal(got, msg2) {
		t.Fatalf("tun1 got %q, want %q", got, msg2)
	}
}

func TestTunnelMultiplePackets(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)
	defer tun1.Close()
	defer tun2.Close()

	for i := 0; i < 100; i++ {
		msg := []byte("packet data for round-trip test")
		if err := tun1.Send(msg); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		got, err := tun2.Receive()
		if err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("packet %d: mismatch", i)
		}
	}
}

func TestTunnelReplayRejection(t *testing.T) {
	// Test the anti-replay bitmap directly.
	tun := &Tunnel{}

	// Epoch 1 should be accepted.
	if !tun.replayCheck(1) {
		t.Fatal("epoch 1 should pass")
	}
	tun.replayCommit(1)

	// Epoch 1 again should be rejected.
	if tun.replayCheck(1) {
		t.Fatal("epoch 1 replay should be rejected")
	}

	// Epoch 2 should be accepted.
	if !tun.replayCheck(2) {
		t.Fatal("epoch 2 should pass")
	}
	tun.replayCommit(2)

	// Epoch 0 is always rejected.
	if tun.replayCheck(0) {
		t.Fatal("epoch 0 should be rejected")
	}

	// Advance past the window — epoch within window should be rejected.
	tun.replayCommit(500)
	tun.replayCommit(400) // mark 400 as seen
	if tun.replayCheck(400) {
		t.Fatal("epoch 400 should be rejected (already seen within window)")
	}
}

func TestTunnelLargePayload(t *testing.T) {
	tun1, tun2 := setupLoopbackTunnels(t)
	defer tun1.Close()
	defer tun2.Close()

	// Send a payload close to typical MTU.
	msg := make([]byte, 1000)
	for i := range msg {
		msg[i] = byte(i % 256)
	}

	if err := tun1.Send(msg); err != nil {
		t.Fatal(err)
	}
	got, err := tun2.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("large payload mismatch")
	}
}

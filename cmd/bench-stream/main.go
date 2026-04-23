// bench-stream measures raw mux throughput across the chameleon tunnel,
// with and without stream mode, for different rate envelopes.
package main

import (
	"crypto/cipher"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"genome/crypto"
	"genome/morph"
	"genome/mux"
	"genome/transport"
)

func main() {
	var (
		bytes      = flag.Int("bytes", 10*1024*1024, "bytes to transfer per run")
		streamMode = flag.Bool("stream", false, "enable stream mode")
		minRate    = flag.Int("min-bps", 100_000, "stream min rate (bytes/sec)")
		maxRate    = flag.Int("max-bps", 700_000, "stream max rate (bytes/sec)")
		chunkBytes = flag.Int("chunk", 32*1024, "Write chunk size")
		idleMode   = flag.Bool("idle", false, "measure idle (chaff-only) wire rate for 3s, no mux traffic")
	)
	flag.Parse()

	if *idleMode {
		runIdle(*minRate, *maxRate)
		return
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	psk := []byte("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe")
	keys, err := crypto.DeriveSessionKeys(psk, nil, crypto.CipherChaCha20Poly1305)
	check(err)

	genome := morph.Derive(keys.GenomeSeed)

	// Loopback UDP pair.
	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	connA, err := net.ListenUDP("udp", addrA)
	check(err)
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	connB, err := net.ListenUDP("udp", addrB)
	check(err)

	// AEAD per side.
	newAEAD := func() cipher.AEAD {
		if genome.NonceSize == 24 {
			a, e := crypto.NewXAEAD(keys.AEADKey)
			check(e)
			return a
		}
		a, e := crypto.NewAEAD(keys.AEADKey, keys.Suite)
		check(e)
		return a
	}

	shaper := transport.NewShaper(0, 0)
	tunA := transport.NewTunnel(connA, connB.LocalAddr().(*net.UDPAddr), newAEAD(), keys.NonceBase, genome, shaper)
	tunB := transport.NewTunnel(connB, connA.LocalAddr().(*net.UDPAddr), newAEAD(), keys.NonceBase, genome, shaper)
	tunA.SetReadTimeout(30 * time.Second)
	tunB.SetReadTimeout(30 * time.Second)

	var burstA, burstB int64
	if *streamMode {
		pA, e := transport.NewStreamPump(tunA, *minRate, *maxRate)
		check(e)
		pA.SetBurstCallback(func() { burstA++ })
		tunA.AttachPump(pA)
		pB, e := transport.NewStreamPump(tunB, *minRate, *maxRate)
		check(e)
		pB.SetBurstCallback(func() { burstB++ })
		tunB.AttachPump(pB)
	}

	sessA := mux.NewSession(tunA, true, logger)  // client (sender)
	sessB := mux.NewSession(tunB, false, logger) // server (receiver)

	// Receiver: accept one stream and drain it.
	type recvResult struct {
		n   int64
		err error
	}
	recvDone := make(chan recvResult, 1)
	go func() {
		st, err := sessB.Accept()
		if err != nil {
			recvDone <- recvResult{0, fmt.Errorf("accept: %w", err)}
			return
		}
		n, err := io.Copy(io.Discard, st)
		recvDone <- recvResult{n, err}
	}()

	// Sender: open a stream and pump bytes.
	time.Sleep(100 * time.Millisecond) // let Accept register
	st, err := sessA.Open("bench", 0)
	check(err)

	buf := make([]byte, *chunkBytes)
	for i := range buf {
		buf[i] = byte(i)
	}

	start := time.Now()
	remaining := *bytes
	var sentBytes int64
	for remaining > 0 {
		n := len(buf)
		if n > remaining {
			n = remaining
		}
		if _, err := st.Write(buf[:n]); err != nil {
			fmt.Fprintf(os.Stderr, "write err: %v\n", err)
			os.Exit(1)
		}
		sentBytes += int64(n)
		remaining -= n
	}
	st.Close()

	res := <-recvDone
	elapsed := time.Since(start)

	mbps := float64(res.n) / 1024 / 1024 / elapsed.Seconds()
	mode := "baseline"
	if *streamMode {
		mode = fmt.Sprintf("stream[%d..%d]", *minRate, *maxRate)
	}
	fmt.Printf("[%s] sent=%d recv=%d elapsed=%s throughput=%.2f MB/s burstA=%d burstB=%d\n",
		mode, sentBytes, res.n, elapsed.Truncate(time.Millisecond), mbps, burstA, burstB)

	sessA.Close()
	sessB.Close()
	tunA.Close()
	tunB.Close()
}

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// runIdle spins up a single pump-equipped tunnel + a draining receiver and
// measures pure-chaff wire rate for 3 seconds. Used to verify the pump
// holds its envelope when no mux traffic is queued.
func runIdle(minRate, maxRate int) {
	psk := []byte("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe")
	keys, err := crypto.DeriveSessionKeys(psk, nil, crypto.CipherChaCha20Poly1305)
	check(err)
	genome := morph.Derive(keys.GenomeSeed)

	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	connA, err := net.ListenUDP("udp", addrA)
	check(err)
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	connB, err := net.ListenUDP("udp", addrB)
	check(err)

	newAEAD := func() cipher.AEAD {
		if genome.NonceSize == 24 {
			a, e := crypto.NewXAEAD(keys.AEADKey)
			check(e)
			return a
		}
		a, e := crypto.NewAEAD(keys.AEADKey, keys.Suite)
		check(e)
		return a
	}
	shaper := transport.NewShaper(0, 0)
	tunA := transport.NewTunnel(connA, connB.LocalAddr().(*net.UDPAddr), newAEAD(), keys.NonceBase, genome, shaper)
	tunB := transport.NewTunnel(connB, connA.LocalAddr().(*net.UDPAddr), newAEAD(), keys.NonceBase, genome, shaper)

	var bytesWire, pkts int64
	tunA.SetStatsCallbacks(
		func(n int) { bytesWire += int64(n); pkts++ },
		nil,
	)

	p, err := transport.NewStreamPump(tunA, minRate, maxRate)
	check(err)
	tunA.AttachPump(p)

	go func() {
		for {
			if _, err := tunB.Receive(); err != nil {
				return
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	bytesWire, pkts = 0, 0

	start := time.Now()
	time.Sleep(3 * time.Second)
	elapsed := time.Since(start)

	wireBps := float64(bytesWire) / elapsed.Seconds()
	fmt.Printf("idle envelope=[%d..%d] wire=%.1f KB/s (%.0f pps) wagon=[%d..%d]\n",
		minRate, maxRate, wireBps/1024, float64(pkts)/elapsed.Seconds(),
		genome.WagonMin, genome.WagonMax)

	tunA.Close()
	tunB.Close()
}

package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"genome/crypto"
	"genome/morph"
	"genome/mux"
	"genome/transport"

	"golang.org/x/net/proxy"
)

// TestEndToEnd verifies the full pipeline:
// HTTP client → SOCKS5 → mux → UDP tunnel → mux → TCP dial → HTTP server
func TestEndToEnd(t *testing.T) {
	// 1. Start a test HTTP server.
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Chameleon", "works")
			fmt.Fprintf(w, "Hello from %s %s", r.Method, r.URL.Path)
		}),
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go httpServer.Serve(httpLn)
	defer httpServer.Close()

	httpAddr := httpLn.Addr().String()
	t.Logf("HTTP server at %s", httpAddr)

	// 2. Set up crypto + genome.
	psk := []byte("integration-test-psk-32bytes!!!!!")
	keys, err := crypto.DeriveSessionKeys(psk, nil, crypto.CipherChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	genome := morph.Derive(keys.GenomeSeed)
	t.Logf("Genome: %s", genome)

	newAEAD := func() interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	} {
		if genome.NonceSize == 24 {
			a, _ := crypto.NewXAEAD(keys.AEADKey)
			return a
		}
		a, _ := crypto.NewAEAD(keys.AEADKey, keys.Suite)
		return a
	}

	// 3. Create UDP tunnel (loopback).
	serverUDPAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	serverUDPConn, err := net.ListenUDP("udp", serverUDPAddr)
	if err != nil {
		t.Fatal(err)
	}

	clientUDPAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	clientUDPConn, err := net.ListenUDP("udp", clientUDPAddr)
	if err != nil {
		t.Fatal(err)
	}

	shaper := transport.NewShaper(0, 0)
	serverTunnel := transport.NewTunnel(serverUDPConn, nil, newAEAD(), keys.NonceBase, genome, shaper)
	clientTunnel := transport.NewTunnel(clientUDPConn, serverUDPConn.LocalAddr().(*net.UDPAddr), newAEAD(), keys.NonceBase, genome, shaper)

	serverTunnel.SetReadTimeout(10 * time.Second)
	clientTunnel.SetReadTimeout(10 * time.Second)

	// 4. Create mux sessions.
	logger := slog.Default()
	serverSession := mux.NewSession(serverTunnel, false, logger)
	clientSession := mux.NewSession(clientTunnel, true, logger)

	// 5. Start server proxy.
	srv := NewServer(serverSession, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	// 6. Start client proxy (SOCKS5 with auth).
	client := NewClient("127.0.0.1:0", clientSession, logger, "testuser", "testpass")
	go client.Run(ctx)
	time.Sleep(100 * time.Millisecond)

	socksAddr := client.SOCKSAddr()
	if socksAddr == nil {
		t.Fatal("SOCKS5 not listening")
	}
	t.Logf("SOCKS5 at %s", socksAddr)

	// 7. Make HTTP request through SOCKS5 proxy with credentials.
	auth := proxy.Auth{User: "testuser", Password: "testpass"}
	dialer, err := proxy.SOCKS5("tcp", socksAddr.String(), &auth, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get("http://" + httpAddr + "/test")
	if err != nil {
		t.Fatalf("HTTP through tunnel: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	expected := "Hello from GET /test"
	if string(body) != expected {
		t.Fatalf("body = %q, want %q", body, expected)
	}

	if resp.Header.Get("X-Chameleon") != "works" {
		t.Fatal("missing X-Chameleon header")
	}

	t.Log("End-to-end test passed!")

	// Cleanup.
	cancel()
	clientSession.Close()
	serverSession.Close()
}

// TestConcurrentStreams tests multiple concurrent connections through the tunnel.
func TestConcurrentStreams(t *testing.T) {
	// HTTP server.
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "req:%s", r.URL.Path)
		}),
	}
	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	go httpServer.Serve(httpLn)
	defer httpServer.Close()
	httpAddr := httpLn.Addr().String()

	// Tunnel setup.
	psk := []byte("concurrent-test-psk-32bytes!!!!!")
	keys, _ := crypto.DeriveSessionKeys(psk, nil, crypto.CipherChaCha20Poly1305)
	genome := morph.Derive(keys.GenomeSeed)

	newAEAD := func() interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	} {
		if genome.NonceSize == 24 {
			a, _ := crypto.NewXAEAD(keys.AEADKey)
			return a
		}
		a, _ := crypto.NewAEAD(keys.AEADKey, keys.Suite)
		return a
	}

	serverUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	clientUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})

	shaper := transport.NewShaper(0, 0)
	serverTunnel := transport.NewTunnel(serverUDP, nil, newAEAD(), keys.NonceBase, genome, shaper)
	clientTunnel := transport.NewTunnel(clientUDP, serverUDP.LocalAddr().(*net.UDPAddr), newAEAD(), keys.NonceBase, genome, shaper)
	serverTunnel.SetReadTimeout(10 * time.Second)
	clientTunnel.SetReadTimeout(10 * time.Second)

	logger := slog.Default()
	serverSess := mux.NewSession(serverTunnel, false, logger)
	clientSess := mux.NewSession(clientTunnel, true, logger)

	srv := NewServer(serverSess, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	client := NewClient("127.0.0.1:0", clientSess, logger, "user2", "pass2")
	go client.Run(ctx)
	time.Sleep(100 * time.Millisecond)

	auth2 := proxy.Auth{User: "user2", Password: "pass2"}
	dialer, _ := proxy.SOCKS5("tcp", client.SOCKSAddr().String(), &auth2, proxy.Direct)
	httpClient := &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   10 * time.Second,
	}

	const numRequests = 10
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			path := fmt.Sprintf("/stream/%d", idx)
			resp, err := httpClient.Get("http://" + httpAddr + path)
			if err != nil {
				errors <- fmt.Errorf("request %d: %v", idx, err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			expected := fmt.Sprintf("req:%s", path)
			if string(body) != expected {
				errors <- fmt.Errorf("request %d: got %q, want %q", idx, body, expected)
			}
		}(i)
	}

	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}

	cancel()
	clientSess.Close()
	serverSess.Close()
}

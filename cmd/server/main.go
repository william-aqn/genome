// Command server runs the Chameleon exit node.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"genome/config"
	"genome/crypto"
	"genome/internal/logger"
	"genome/morph"
	"genome/mux"
	"genome/proxy"
	"genome/transport"
)

func main() {
	var (
		cfgPath    = flag.String("config", "", "path to config JSON file")
		listenAddr = flag.String("listen", ":9000", "UDP listen address")
		pskHex     = flag.String("psk", "", "pre-shared key (hex)")
		cipher     = flag.String("cipher", "chacha20", "cipher suite: chacha20 or aes256gcm")
		logLevel   = flag.String("log", "info", "log level: debug, info, warn, error")
	)
	flag.Parse()

	var cfg config.Config
	if *cfgPath != "" {
		loaded, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		cfg = *loaded
	} else {
		cfg = config.Config{
			PSKHex:          *pskHex,
			ListenAddr:      *listenAddr,
			CipherSuiteName: *cipher,
			LogLevel:        *logLevel,
		}
		cfg.Defaults()
	}

	if cfg.PSKHex == "" {
		fmt.Fprintln(os.Stderr, "Error: PSK is required. Use -psk flag or config file.")
		os.Exit(1)
	}

	log := logger.New(cfg.LogLevel)

	psk, err := hex.DecodeString(cfg.PSKHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid PSK hex: %v\n", err)
		os.Exit(1)
	}

	suite := cfg.CipherSuite()
	keys, err := crypto.DeriveSessionKeys(psk, nil, suite)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: deriving keys: %v\n", err)
		os.Exit(1)
	}

	genome := morph.Derive(keys.GenomeSeed)
	log.Info("genome derived", "genome", genome.String())

	aead, err := newAEAD(keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: creating AEAD: %v\n", err)
		os.Exit(1)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: resolving address: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: listen UDP: %v\n", err)
		os.Exit(1)
	}

	shaper := transport.NewShaper(0, 0) // no shaping on server
	tunnel := transport.NewTunnel(conn, nil, aead, keys.NonceBase, genome, shaper)
	tunnel.SetDropCallback(func(reason string, err error) {
		log.Warn("packet dropped", "reason", reason, "err", err)
	})

	session := mux.NewSession(tunnel, false, log)
	session.SetIdleTimeout(0) // server waits forever for clients

	// When peer address changes (client reconnect), close all old streams.
	tunnel.SetPeerResetCallback(func() {
		log.Info("peer address changed, resetting streams")
		session.ResetStreams()
	})

	srv := proxy.NewServer(session, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("shutting down...")
		cancel()
		session.Close()
	}()

	log.Info("chameleon server started", "listen", cfg.ListenAddr)
	if err := srv.Run(ctx); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}

func newAEAD(keys *crypto.SessionKeys) (interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
}, error) {
	genome := morph.Derive(keys.GenomeSeed)
	if genome.NonceSize == 24 {
		return crypto.NewXAEAD(keys.AEADKey)
	}
	return crypto.NewAEAD(keys.AEADKey, keys.Suite)
}

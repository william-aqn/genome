// Command client runs the Chameleon SOCKS5 proxy and tunnel client.
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
		serverAddr = flag.String("server", "", "server UDP address (host:port)")
		socksAddr  = flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address")
		socksUser  = flag.String("socks-user", "", "SOCKS5 username (enables auth)")
		socksPass  = flag.String("socks-pass", "", "SOCKS5 password (enables auth)")
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
			ListenAddr:      ":0", // ephemeral port for client
			PeerAddr:        *serverAddr,
			SOCKSAddr:       *socksAddr,
			SOCKSUser:       *socksUser,
			SOCKSPass:       *socksPass,
			CipherSuiteName: *cipher,
			LogLevel:        *logLevel,
		}
		cfg.Defaults()
	}

	if cfg.PSKHex == "" {
		fmt.Fprintln(os.Stderr, "Error: PSK is required. Use -psk flag or config file.")
		os.Exit(1)
	}
	if cfg.PeerAddr == "" {
		fmt.Fprintln(os.Stderr, "Error: server address is required. Use -server flag or config file.")
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

	// Resolve server address.
	peerUDP, err := net.ResolveUDPAddr("udp", cfg.PeerAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: resolving server: %v\n", err)
		os.Exit(1)
	}

	// Bind local UDP.
	localAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: resolving local: %v\n", err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: listen UDP: %v\n", err)
		os.Exit(1)
	}

	shaper := transport.NewShaper(0, 0)
	tunnel := transport.NewTunnel(conn, peerUDP, aead, keys.NonceBase, genome, shaper)
	tunnel.SetDropCallback(func(reason string, err error) {
		log.Warn("packet dropped", "reason", reason, "err", err)
	})

	session := mux.NewSession(tunnel, true, log)
	if cfg.IdleTimeout() > 0 {
		session.SetIdleTimeout(cfg.IdleTimeout())
	}

	client := proxy.NewClient(cfg.SOCKSAddr, session, log, cfg.SOCKSUser, cfg.SOCKSPass)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("shutting down...")
		cancel()
		client.Close()
		session.Close()
	}()

	log.Info("chameleon client started",
		"socks", cfg.SOCKSAddr,
		"server", cfg.PeerAddr)

	if err := client.Run(ctx); err != nil {
		log.Error("client error", "err", err)
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

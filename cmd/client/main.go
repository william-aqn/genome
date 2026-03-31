// Command client runs the Chameleon SOCKS5 proxy and tunnel client.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
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
		socksAddr  = flag.String("socks", "", "SOCKS5 listen address")
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
	} else if *pskHex != "" && *serverAddr != "" {
		// All from flags.
		cfg = config.Config{
			PSKHex:          *pskHex,
			ListenAddr:      ":0",
			PeerAddr:        *serverAddr,
			SOCKSAddr:       *socksAddr,
			SOCKSUser:       *socksUser,
			SOCKSPass:       *socksPass,
			CipherSuiteName: *cipher,
			LogLevel:        *logLevel,
		}
	} else {
		// Interactive mode.
		cfg = interactiveSetup()
		cfg.CipherSuiteName = *cipher
		if *logLevel != "" {
			cfg.LogLevel = *logLevel
		}
	}
	cfg.Defaults()

	// Generate random SOCKS credentials if not set.
	if cfg.SOCKSUser == "" {
		cfg.SOCKSUser = randomString(8)
	}
	if cfg.SOCKSPass == "" {
		cfg.SOCKSPass = randomString(12)
	}
	// Generate random SOCKS port if not set.
	if cfg.SOCKSAddr == "" || cfg.SOCKSAddr == "127.0.0.1:1080" {
		port := randomPort()
		cfg.SOCKSAddr = fmt.Sprintf("127.0.0.1:%d", port)
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

	peerUDP, err := net.ResolveUDPAddr("udp", cfg.PeerAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: resolving server: %v\n", err)
		os.Exit(1)
	}

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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
		client.Close()
		session.Close()
	}()

	fmt.Println()
	fmt.Println("===========================================")
	fmt.Printf("  SOCKS5 proxy:  %s\n", cfg.SOCKSAddr)
	fmt.Printf("  Username:      %s\n", cfg.SOCKSUser)
	fmt.Printf("  Password:      %s\n", cfg.SOCKSPass)
	fmt.Printf("  Server:        %s\n", cfg.PeerAddr)
	fmt.Println("===========================================")
	fmt.Println("  Configure your browser/app to use SOCKS5")
	fmt.Printf("  proxy at %s with the credentials above.\n", cfg.SOCKSAddr)
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println("===========================================")
	fmt.Println()

	if err := client.Run(ctx); err != nil {
		log.Error("client error", "err", err)
		os.Exit(1)
	}
}

// interactiveSetup prompts the user for connection parameters.
func interactiveSetup() config.Config {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Chameleon Client — Interactive Setup")
	fmt.Println()

	serverIP := prompt(reader, "Server IP", "")
	serverPort := prompt(reader, "Server port", "9000")
	psk := prompt(reader, "PSK (hex)", "")
	socksPort := prompt(reader, fmt.Sprintf("SOCKS5 port [random=%d]", randomPort()), "")
	socksUser := prompt(reader, fmt.Sprintf("SOCKS5 username [random=%s]", "auto"), "")
	socksPass := prompt(reader, fmt.Sprintf("SOCKS5 password [random=%s]", "auto"), "")

	socksAddr := ""
	if socksPort != "" {
		socksAddr = "127.0.0.1:" + socksPort
	}

	return config.Config{
		PSKHex:     psk,
		ListenAddr: ":0",
		PeerAddr:   net.JoinHostPort(serverIP, serverPort),
		SOCKSAddr:  socksAddr,
		SOCKSUser:  socksUser,
		SOCKSPass:  socksPass,
		LogLevel:   "info",
	}
}

func prompt(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("  %s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

func randomPort() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(40000))
	return int(n.Int64()) + 10000
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
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

// Command client runs the Chameleon SOCKS5 proxy and tunnel client.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"genome/config"
	"genome/crypto"
	"genome/internal/dashboard"
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
		noUI       = flag.Bool("no-ui", false, "disable dashboard, plain log output")
		noAuth     = flag.Bool("no-auth", false, "disable SOCKS5 authentication")
	)
	flag.Parse()

	// Auto-detect client.json next to executable.
	if *cfgPath == "" {
		if exe, err := os.Executable(); err == nil {
			autoPath := filepath.Join(filepath.Dir(exe), "client.json")
			if _, err := os.Stat(autoPath); err == nil {
				*cfgPath = autoPath
			}
		}
	}

	var cfg config.Config
	if *cfgPath != "" {
		loaded, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		cfg = *loaded
		fmt.Printf("Loaded config: %s\n", *cfgPath)
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

	// Disable auth if requested.
	if *noAuth {
		cfg.SOCKSUser = ""
		cfg.SOCKSPass = ""
	}

	// Generate random SOCKS credentials/port only for fresh configs (not loaded from file).
	fromFile := *cfgPath != ""
	if !fromFile && !*noAuth {
		if cfg.SOCKSUser == "" {
			cfg.SOCKSUser = randomString(8)
		}
		if cfg.SOCKSPass == "" {
			cfg.SOCKSPass = randomString(12)
		}
		if cfg.SOCKSAddr == "" || cfg.SOCKSAddr == "127.0.0.1:1080" {
			port := randomPort()
			cfg.SOCKSAddr = fmt.Sprintf("127.0.0.1:%d", port)
		}
		saveConfig(&cfg)
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

	// --- Stats + Dashboard ---
	stats := &dashboard.Stats{}
	useUI := !*noUI

	shaper := transport.NewShaper(0, 0)
	tunnel := transport.NewTunnel(conn, peerUDP, aead, keys.NonceBase, genome, shaper)

	var dash *dashboard.Dashboard
	if useUI {
		dash = dashboard.New(stats, cfg.SOCKSAddr, cfg.SOCKSUser, cfg.SOCKSPass, cfg.PeerAddr)
	}

	tunnel.SetDropCallback(func(reason string, err error) {
		stats.PacketsDropped.Add(1)
		if dash != nil {
			dash.Log(fmt.Sprintf("DROP %s: %v", reason, err))
		} else {
			log.Warn("packet dropped", "reason", reason, "err", err)
		}
	})
	tunnel.SetStatsCallbacks(
		func(n int) { stats.BytesSent.Add(int64(n)); stats.PacketsSent.Add(1) },
		func(n int) { stats.BytesRecv.Add(int64(n)); stats.PacketsRecv.Add(1) },
	)

	session := mux.NewSession(tunnel, true, log)
	if cfg.IdleTimeout() > 0 {
		session.SetIdleTimeout(cfg.IdleTimeout())
	}
	session.SetStreamCallbacks(
		func() {
			stats.OpenStreams.Add(1)
			stats.TotalStreams.Add(1)
		},
		func() { stats.OpenStreams.Add(-1) },
	)

	client := proxy.NewClient(cfg.SOCKSAddr, session, log, cfg.SOCKSUser, cfg.SOCKSPass)

	if dash != nil {
		client.SetConnectLogger(func(dest string) {
			dash.LogRequest(dest)
		})
	} else {
		client.SetConnectLogger(func(dest string) {
			log.Info("connect", "dest", dest)
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if dash != nil {
			dash.Stop()
		}
		fmt.Println("\nShutting down...")
		cancel()
		client.Close()
		session.Close()
	}()

	if dash != nil {
		go dash.Run()
	} else {
		log.Info("chameleon client started",
			"socks", cfg.SOCKSAddr,
			"user", cfg.SOCKSUser,
			"server", cfg.PeerAddr)
	}

	if err := client.Run(ctx); err != nil {
		if dash != nil {
			dash.Stop()
		}
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

func saveConfig(cfg *config.Config) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cfgPath := filepath.Join(filepath.Dir(exe), "client.json")

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save config: %v\n", err)
		return
	}
	fmt.Printf("  Config saved: %s\n", cfgPath)
	fmt.Printf("  Next time run: chameleon-client -config %s\n", cfgPath)
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

// Package config provides configuration for the Chameleon tunnel.
package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"genome/crypto"
)

// Config holds all configuration for a Chameleon node.
type Config struct {
	// PSK is the pre-shared key (hex-encoded or raw bytes).
	PSKHex string `json:"psk"`

	// ListenAddr is the UDP listen address for the tunnel.
	ListenAddr string `json:"listen_addr"`

	// PeerAddr is the UDP address of the remote peer (client only).
	PeerAddr string `json:"peer_addr,omitempty"`

	// SOCKSAddr is the SOCKS5 listen address (client only).
	SOCKSAddr string `json:"socks_addr,omitempty"`

	// CipherSuite selects the AEAD algorithm.
	// "chacha20" (default) or "aes256gcm".
	CipherSuiteName string `json:"cipher_suite,omitempty"`

	// SOCKS5 authentication (client only). If both set, RFC 1929 auth is required.
	SOCKSUser string `json:"socks_user,omitempty"`
	SOCKSPass string `json:"socks_pass,omitempty"`

	// LogLevel: "debug", "info", "warn", "error".
	LogLevel string `json:"log_level,omitempty"`

	// IdleTimeout for the tunnel session.
	IdleTimeoutSec int `json:"idle_timeout_sec,omitempty"`

	// StreamMode enables constant-rate cover traffic ("поток"). When set,
	// the tunnel emits a steady flow of genome-sized "wagons" regardless
	// of real user activity, carrying real data when present and random
	// chaff otherwise. Both endpoints must enable it for traffic to parse.
	StreamMode bool `json:"stream_mode,omitempty"`

	// StreamMinBytesPerSec is the lower bound of the chaff-flow rate
	// envelope (plaintext bytes/sec). The pump's current target rate drifts
	// randomly between this and StreamMaxBytesPerSec.
	StreamMinBytesPerSec int `json:"stream_min_bytes_per_sec,omitempty"`

	// StreamMaxBytesPerSec is the upper bound of the chaff-flow rate
	// envelope. When the real-data queue backs up the pump bursts beyond
	// this cap and drains "as is".
	StreamMaxBytesPerSec int `json:"stream_max_bytes_per_sec,omitempty"`
}

// Defaults fills in default values for unset fields.
func (c *Config) Defaults() {
	if c.SOCKSAddr == "" {
		c.SOCKSAddr = "127.0.0.1:1080"
	}
	if c.CipherSuiteName == "" {
		c.CipherSuiteName = "chacha20"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.IdleTimeoutSec == 0 {
		c.IdleTimeoutSec = 300 // 5 minutes
	}
	if c.StreamMode {
		if c.StreamMinBytesPerSec == 0 {
			c.StreamMinBytesPerSec = 100_000 // ~100 KB/s
		}
		if c.StreamMaxBytesPerSec == 0 {
			c.StreamMaxBytesPerSec = 700_000 // ~700 KB/s
		}
	}
}

// Validate checks that required fields are present and valid.
func (c *Config) Validate() error {
	if c.PSKHex == "" {
		return fmt.Errorf("config: psk is required")
	}
	psk, err := c.PSK()
	if err != nil {
		return err
	}
	if len(psk) < 16 {
		return fmt.Errorf("config: PSK too short (%d bytes, minimum 16)", len(psk))
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr is required")
	}
	if c.StreamMode {
		if c.StreamMinBytesPerSec < 1_000 || c.StreamMinBytesPerSec > 100_000_000 {
			return fmt.Errorf("config: stream_min_bytes_per_sec=%d out of range [1000, 1e8]", c.StreamMinBytesPerSec)
		}
		if c.StreamMaxBytesPerSec < c.StreamMinBytesPerSec || c.StreamMaxBytesPerSec > 100_000_000 {
			return fmt.Errorf("config: stream_max_bytes_per_sec=%d must be ≥ min and ≤ 1e8", c.StreamMaxBytesPerSec)
		}
	}
	return nil
}

// PSK decodes the hex-encoded PSK.
func (c *Config) PSK() ([]byte, error) {
	psk, err := hex.DecodeString(c.PSKHex)
	if err != nil {
		return nil, fmt.Errorf("config: invalid hex PSK: %w", err)
	}
	return psk, nil
}

// CipherSuite returns the selected cipher suite.
func (c *Config) CipherSuite() crypto.CipherSuite {
	switch c.CipherSuiteName {
	case "aes256gcm", "aes":
		return crypto.CipherAES256GCM
	default:
		return crypto.CipherChaCha20Poly1305
	}
}

// IdleTimeout returns the idle timeout duration.
func (c *Config) IdleTimeout() time.Duration {
	return time.Duration(c.IdleTimeoutSec) * time.Second
}

// Load reads a config from a JSON file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	cfg.Defaults()
	return &cfg, nil
}

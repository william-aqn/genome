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

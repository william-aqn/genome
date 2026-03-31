package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"genome/crypto"
	"genome/morph"
	"genome/mux"
	"genome/transport"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: probe <server:port> <psk-hex>")
		return
	}
	serverAddr := os.Args[1]
	psk, err := hex.DecodeString(os.Args[2])
	if err != nil {
		fmt.Println("invalid PSK hex:", err)
		return
	}

	keys, err := crypto.DeriveSessionKeys(psk, nil, crypto.CipherChaCha20Poly1305)
	if err != nil {
		fmt.Println("key derivation error:", err)
		return
	}

	genome := morph.Derive(keys.GenomeSeed)
	fmt.Printf("Genome: %s\n", genome)

	var aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
	if genome.NonceSize == 24 {
		aead, err = crypto.NewXAEAD(keys.AEADKey)
	} else {
		aead, err = crypto.NewAEAD(keys.AEADKey, keys.Suite)
	}
	if err != nil {
		fmt.Println("AEAD error:", err)
		return
	}

	peerUDP, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		fmt.Println("resolve error:", err)
		return
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		fmt.Println("listen error:", err)
		return
	}
	defer conn.Close()

	shaper := transport.NewShaper(0, 0)
	tunnel := transport.NewTunnel(conn, peerUDP, aead, keys.NonceBase, genome, shaper)
	tunnel.SetReadTimeout(10 * time.Second)
	tunnel.SetDropCallback(func(reason string, err error) {
		fmt.Printf("  [DROP] reason=%s err=%v\n", reason, err)
	})

	// Send OPEN command.
	cmd := &mux.Command{
		Type:     mux.CmdOpen,
		StreamID: 1,
		DestAddr: "example.com",
		DestPort: 80,
	}
	data, err := mux.EncodeCommand(cmd)
	if err != nil {
		fmt.Println("encode error:", err)
		return
	}

	fmt.Printf("Sending OPEN to %s...\n", serverAddr)
	if err := tunnel.Send(data); err != nil {
		fmt.Println("send error:", err)
		return
	}
	fmt.Println("Sent. Waiting 10s for responses (will show all drops)...")

	for i := 0; i < 3; i++ {
		resp, err := tunnel.Receive()
		if err != nil {
			fmt.Println("receive error:", err)
			break
		}
		respCmd, err := mux.DecodeCommand(resp)
		if err != nil {
			fmt.Printf("got %d bytes, decode failed: %v\n", len(resp), err)
			continue
		}
		fmt.Printf(">>> Response: type=0x%02x stream=%d\n", respCmd.Type, respCmd.StreamID)
		if respCmd.Type == mux.CmdData {
			fmt.Printf("    data (%d bytes): %q\n", len(respCmd.Data), string(respCmd.Data))
		}
	}
}

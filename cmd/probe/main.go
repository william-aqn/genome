package main

import (
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
	pskHex := os.Args[2]

	psk := make([]byte, len(pskHex)/2)
	for i := 0; i < len(psk); i++ {
		fmt.Sscanf(pskHex[i*2:i*2+2], "%02x", &psk[i])
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

	// Send an OPEN command (like a real client would).
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

	fmt.Printf("Sending OPEN command (%d bytes) to %s...\n", len(data), serverAddr)
	if err := tunnel.Send(data); err != nil {
		fmt.Println("send error:", err)
		return
	}
	fmt.Println("Sent OK. Waiting for response...")

	resp, err := tunnel.Receive()
	if err != nil {
		fmt.Println("receive error:", err)
		fmt.Println(">>> Server is NOT responding. Check firewall / server logs.")
		return
	}

	respCmd, err := mux.DecodeCommand(resp)
	if err != nil {
		fmt.Printf("Got %d bytes back but decode failed: %v\n", len(resp), err)
		return
	}

	fmt.Printf(">>> Got response: type=0x%02x stream=%d\n", respCmd.Type, respCmd.StreamID)
	fmt.Println(">>> Tunnel is working!")
}

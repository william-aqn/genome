package socks5

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestSOCKS5ConnectIPv4(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := func(ctx context.Context, destAddr string, destPort uint16, clientConn net.Conn) error {
		if destAddr != "93.184.216.34" || destPort != 80 {
			return fmt.Errorf("unexpected dest: %s:%d", destAddr, destPort)
		}
		// Echo back.
		buf := make([]byte, 100)
		n, _ := clientConn.Read(buf)
		clientConn.Write(buf[:n])
		return nil
	}

	srv := New("127.0.0.1:0", handler, slog.Default())
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("server not listening")
	}

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Negotiation: no auth.
	conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("negotiation: %x", resp)
	}

	// CONNECT to 93.184.216.34:80.
	conn.Write([]byte{
		0x05, 0x01, 0x00, 0x01, // VER CMD RSV ATYP(IPv4)
		93, 184, 216, 34, // IP
		0x00, 0x50, // port 80
	})

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != 0x00 {
		t.Fatalf("connect reply: 0x%02x", reply[1])
	}

	// Send data, expect echo.
	conn.Write([]byte("hello"))
	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Fatalf("echo: %q", buf[:n])
	}
}

func TestSOCKS5ConnectDomain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gotAddr string
	var gotPort uint16
	handler := func(ctx context.Context, destAddr string, destPort uint16, clientConn net.Conn) error {
		gotAddr = destAddr
		gotPort = destPort
		clientConn.Write([]byte("ok"))
		return nil
	}

	srv := New("127.0.0.1:0", handler, slog.Default())
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Negotiation.
	conn.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(conn, make([]byte, 2))

	// CONNECT to example.com:443 (domain type).
	domain := "example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req = append(req, []byte(domain)...)
	req = append(req, 0x01, 0xBB) // port 443
	conn.Write(req)

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != 0x00 {
		t.Fatalf("reply: 0x%02x", reply[1])
	}

	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "ok" {
		t.Fatalf("got %q", buf[:n])
	}

	if gotAddr != "example.com" || gotPort != 443 {
		t.Fatalf("handler got %s:%d", gotAddr, gotPort)
	}
}

func TestSOCKS5AuthSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := func(ctx context.Context, destAddr string, destPort uint16, clientConn net.Conn) error {
		clientConn.Write([]byte("authed"))
		return nil
	}

	srv := New("127.0.0.1:0", handler, slog.Default())
	srv.SetAuth("user", "pass123")
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Offer username/password method.
	conn.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)
	if resp[1] != 0x02 {
		t.Fatalf("expected auth method 0x02, got 0x%02x", resp[1])
	}

	// RFC 1929: VER=0x01 ULEN USER PLEN PASS
	auth := []byte{0x01, 4, 'u', 's', 'e', 'r', 7, 'p', 'a', 's', 's', '1', '2', '3'}
	conn.Write(auth)
	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	if authResp[1] != 0x00 {
		t.Fatalf("auth failed: 0x%02x", authResp[1])
	}

	// CONNECT.
	conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50})
	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != 0x00 {
		t.Fatalf("connect failed: 0x%02x", reply[1])
	}

	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "authed" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestSOCKS5AuthBadPassword(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := func(ctx context.Context, destAddr string, destPort uint16, clientConn net.Conn) error {
		return nil
	}

	srv := New("127.0.0.1:0", handler, slog.Default())
	srv.SetAuth("user", "correct")
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)

	// Wrong password.
	auth := []byte{0x01, 4, 'u', 's', 'e', 'r', 5, 'w', 'r', 'o', 'n', 'g'}
	conn.Write(auth)
	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	if authResp[1] != 0x01 {
		t.Fatalf("expected auth failure 0x01, got 0x%02x", authResp[1])
	}
}

func TestSOCKS5AuthRequiredButClientNoAuth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := func(ctx context.Context, destAddr string, destPort uint16, clientConn net.Conn) error {
		return nil
	}

	srv := New("127.0.0.1:0", handler, slog.Default())
	srv.SetAuth("user", "pass")
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Client only offers no-auth (0x00), but server requires 0x02.
	conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)
	if resp[1] != 0xFF {
		t.Fatalf("expected 0xFF (no acceptable method), got 0x%02x", resp[1])
	}
}

func TestSOCKS5UnsupportedCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := func(ctx context.Context, destAddr string, destPort uint16, clientConn net.Conn) error {
		return nil
	}

	srv := New("127.0.0.1:0", handler, slog.Default())
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Negotiation.
	conn.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(conn, make([]byte, 2))

	// BIND command (0x02) — unsupported.
	conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x50})
	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != repCmdNotSupported {
		t.Fatalf("expected cmd-not-supported (0x%02x), got 0x%02x", repCmdNotSupported, reply[1])
	}
}

// Package socks5 implements a minimal SOCKS5 server supporting only the CONNECT command.
package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
)

const (
	socksVersion = 0x05

	// Authentication methods.
	authNone = 0x00
	authNO   = 0xFF

	// Commands.
	cmdConnect = 0x01

	// Address types.
	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

	// Reply codes.
	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repNotAllowed      = 0x02
	repNetworkUnreach  = 0x03
	repHostUnreach     = 0x04
	repConnRefused     = 0x05
	repTTLExpired      = 0x06
	repCmdNotSupported = 0x07
	repAddrNotSupp     = 0x08
)

// ConnectHandler is called when a SOCKS5 CONNECT request is received.
// The handler should establish the upstream connection and perform
// bidirectional data relay. clientConn is the raw TCP connection
// after SOCKS5 negotiation is complete (success reply already sent).
type ConnectHandler func(ctx context.Context, destAddr string, destPort uint16, clientConn net.Conn) error

// Server is a minimal SOCKS5 proxy server.
type Server struct {
	listenAddr string
	handler    ConnectHandler
	logger     *slog.Logger
	listener   net.Listener
	mu         sync.Mutex
}

// New creates a SOCKS5 server.
func New(listenAddr string, handler ConnectHandler, logger *slog.Logger) *Server {
	return &Server{
		listenAddr: listenAddr,
		handler:    handler,
		logger:     logger,
	}
}

// ListenAndServe starts accepting SOCKS5 connections.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("socks5: listen: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	s.logger.Info("SOCKS5 server listening", "addr", ln.Addr())

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("socks5: accept: %w", err)
			}
		}
		go s.handleConn(ctx, conn)
	}
}

// Close stops the SOCKS5 server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the listener address (useful when listening on :0).
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Phase 1: Method negotiation.
	if err := s.negotiate(conn); err != nil {
		s.logger.Debug("socks5 negotiation failed", "err", err)
		return
	}

	// Phase 2: Read request.
	destAddr, destPort, err := s.readRequest(conn)
	if err != nil {
		s.logger.Debug("socks5 request failed", "err", err)
		return
	}

	// Send success reply.
	if err := s.sendReply(conn, repSuccess, "0.0.0.0", 0); err != nil {
		s.logger.Debug("socks5 reply failed", "err", err)
		return
	}

	s.logger.Debug("socks5 connect", "dest", fmt.Sprintf("%s:%d", destAddr, destPort))

	// Phase 3: Hand off to handler.
	if err := s.handler(ctx, destAddr, destPort, conn); err != nil {
		s.logger.Debug("socks5 handler error", "err", err, "dest", fmt.Sprintf("%s:%d", destAddr, destPort))
	}
}

func (s *Server) negotiate(conn net.Conn) error {
	// Read: VER NMETHODS METHODS...
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("reading version: %w", err)
	}
	if buf[0] != socksVersion {
		return fmt.Errorf("unsupported version: %d", buf[0])
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("reading methods: %w", err)
	}

	// We only support no-auth.
	hasNoAuth := false
	for _, m := range methods {
		if m == authNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		conn.Write([]byte{socksVersion, authNO})
		return fmt.Errorf("no acceptable auth method")
	}

	// Reply: VER METHOD
	_, err := conn.Write([]byte{socksVersion, authNone})
	return err
}

func (s *Server) readRequest(conn net.Conn) (string, uint16, error) {
	// VER CMD RSV ATYP DST.ADDR DST.PORT
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, fmt.Errorf("reading request header: %w", err)
	}

	if header[0] != socksVersion {
		return "", 0, fmt.Errorf("bad version in request: %d", header[0])
	}

	if header[1] != cmdConnect {
		s.sendReply(conn, repCmdNotSupported, "0.0.0.0", 0)
		return "", 0, fmt.Errorf("unsupported command: 0x%02x", header[1])
	}

	var destAddr string
	switch header[3] {
	case addrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, fmt.Errorf("reading IPv4 addr: %w", err)
		}
		destAddr = net.IP(addr).String()

	case addrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, fmt.Errorf("reading domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, fmt.Errorf("reading domain: %w", err)
		}
		destAddr = string(domain)

	case addrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, fmt.Errorf("reading IPv6 addr: %w", err)
		}
		destAddr = net.IP(addr).String()

	default:
		s.sendReply(conn, repAddrNotSupp, "0.0.0.0", 0)
		return "", 0, fmt.Errorf("unsupported address type: 0x%02x", header[3])
	}

	// Read port (2 bytes, big-endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, fmt.Errorf("reading port: %w", err)
	}
	destPort := binary.BigEndian.Uint16(portBuf)

	return destAddr, destPort, nil
}

func (s *Server) sendReply(conn net.Conn, rep byte, bindAddr string, bindPort uint16) error {
	ip := net.ParseIP(bindAddr)
	if ip == nil {
		ip = net.IPv4zero
	}

	var atyp byte
	var addr []byte
	if v4 := ip.To4(); v4 != nil {
		atyp = addrIPv4
		addr = v4
	} else {
		atyp = addrIPv6
		addr = ip.To16()
	}

	reply := make([]byte, 4+len(addr)+2)
	reply[0] = socksVersion
	reply[1] = rep
	reply[2] = 0x00 // RSV
	reply[3] = atyp
	copy(reply[4:], addr)
	binary.BigEndian.PutUint16(reply[4+len(addr):], bindPort)

	_, err := conn.Write(reply)
	return err
}

// FormatAddr formats a host:port pair for net.Dial.
func FormatAddr(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

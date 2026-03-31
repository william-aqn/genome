// Package proxy wires together the SOCKS5 server and the mux session.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"

	"genome/mux"
	"genome/socks5"
)

// Client is the client-side proxy: SOCKS5 → mux → tunnel.
type Client struct {
	socks   *socks5.Server
	session *mux.Session
	logger  *slog.Logger
}

// NewClient creates a client proxy. If username/password are non-empty,
// SOCKS5 will require RFC 1929 authentication.
func NewClient(socksAddr string, session *mux.Session, logger *slog.Logger, username, password string) *Client {
	c := &Client{
		session: session,
		logger:  logger,
	}
	c.socks = socks5.New(socksAddr, c.handleConnect, logger)
	if username != "" && password != "" {
		c.socks.SetAuth(username, password)
	}
	return c
}

// Run starts the SOCKS5 server and blocks until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	return c.socks.ListenAndServe(ctx)
}

// Close shuts down the client proxy.
func (c *Client) Close() error {
	return c.socks.Close()
}

// SOCKSAddr returns the SOCKS5 listener address.
func (c *Client) SOCKSAddr() net.Addr {
	return c.socks.Addr()
}

func (c *Client) handleConnect(ctx context.Context, destAddr string, destPort uint16, clientConn net.Conn) error {
	stream, err := c.session.Open(destAddr, destPort)
	if err != nil {
		return err
	}

	relay(clientConn, stream, c.logger)
	return nil
}

// relay performs bidirectional copy between a net.Conn and a mux.Stream.
func relay(local net.Conn, remote io.ReadWriteCloser, logger *slog.Logger) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(remote, local)
		remote.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(local, remote)
		local.Close()
	}()

	wg.Wait()
}

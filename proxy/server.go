package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"genome/mux"
	"genome/socks5"
)

const (
	dialTimeout    = 10 * time.Second
	maxConcStreams = 1024
)

// Server is the server-side proxy: mux → dial TCP → relay.
type Server struct {
	session *mux.Session
	dialer  *net.Dialer
	logger  *slog.Logger
	sem     chan struct{} // concurrency limiter
}

// NewServer creates a server proxy.
func NewServer(session *mux.Session, logger *slog.Logger) *Server {
	return &Server{
		session: session,
		dialer:  &net.Dialer{Timeout: dialTimeout},
		logger:  logger,
		sem:     make(chan struct{}, maxConcStreams),
	}
}

// Run accepts mux streams and relays them to real TCP destinations.
// Blocks until ctx is cancelled or session closes.
func (s *Server) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.session.Done():
			return nil
		default:
		}

		stream, err := s.session.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.session.Done():
				return nil
			default:
				s.logger.Error("accept stream error", "err", err)
				return err
			}
		}

		s.sem <- struct{}{} // acquire
		go func() {
			defer func() { <-s.sem }() // release
			s.handleStream(ctx, stream)
		}()
	}
}

func (s *Server) handleStream(ctx context.Context, stream *mux.Stream) {
	addr := socks5.FormatAddr(stream.DestAddr(), stream.DestPort())
	s.logger.Debug("dialing destination", "addr", addr, "stream_id", stream.ID())

	conn, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		s.logger.Warn("dial failed", "addr", addr, "err", err)
		stream.Close()
		return
	}

	s.logger.Debug("connected to destination", "addr", addr, "stream_id", stream.ID())

	// Bidirectional relay.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
		conn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(stream, conn)
		stream.Close()
	}()

	wg.Wait()
	conn.Close()
}

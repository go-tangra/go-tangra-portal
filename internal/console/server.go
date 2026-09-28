package console

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ServerOptions configure the console listener. The certificate is the
// edge's public certificate (same host name, different port).
type ServerOptions struct {
	Addr              string
	CertFile, KeyFile string
	ReloadInterval    time.Duration // default 1m
	HandshakeTimeout  time.Duration // TLS handshake and request headers (default 10s)
	IdleTimeout       time.Duration // default 60s
	MaxHeaderBytes    int           // default 8 KiB
	Logger            *slog.Logger
}

// Server is the console listener: TLS 1.3 only, HTTP/1.1 only (WebSocket
// upgrades need it and the listener serves nothing else), certificate
// reloaded from disk. It implements the Kratos transport.Server contract.
type Server struct {
	o    ServerOptions
	srv  *http.Server
	lis  net.Listener
	cert atomic.Pointer[tls.Certificate]
	hash [32]byte
	mu   sync.Mutex
	stop chan struct{}
	once sync.Once
}

// NewServer loads the certificate and binds the listener (a busy port fails
// fast). No plain-text or TLS < 1.3 connection is ever served.
func NewServer(o ServerOptions, h http.Handler) (*Server, error) {
	if h == nil {
		return nil, errors.New("console: handler is required")
	}
	if o.CertFile == "" || o.KeyFile == "" {
		return nil, errors.New("console: cert_file and key_file are required")
	}
	if o.ReloadInterval <= 0 {
		o.ReloadInterval = time.Minute
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 60 * time.Second
	}
	if o.MaxHeaderBytes <= 0 {
		o.MaxHeaderBytes = 8 << 10
	}
	s := &Server{o: o, stop: make(chan struct{})}
	if err := s.reload(); err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
		NextProtos:     []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.cert.Load(), nil },
	}
	raw, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return nil, fmt.Errorf("console: listen: %w", err)
	}
	s.lis = tls.NewListener(raw, tlsCfg)
	// No ReadTimeout/WriteTimeout: they are connection deadlines that would
	// cut relayed WebSockets; the handler bounds every request by context.
	// ReadHeaderTimeout also bounds the TLS handshake.
	s.srv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: o.HandshakeTimeout,
		IdleTimeout:       o.IdleTimeout,
		MaxHeaderBytes:    o.MaxHeaderBytes,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){}, // never HTTP/2
	}
	if o.Logger != nil {
		s.srv.ErrorLog = slog.NewLogLogger(o.Logger.Handler(), slog.LevelWarn)
	}
	return s, nil
}

// Addr is the bound address.
func (s *Server) Addr() string { return s.lis.Addr().String() }

// Start serves until Stop.
func (s *Server) Start(context.Context) error {
	go s.reloadLoop()
	if err := s.srv.Serve(s.lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Stop closes the listener and drains in-flight requests.
func (s *Server) Stop(ctx context.Context) error {
	s.once.Do(func() { close(s.stop) })
	err := s.srv.Shutdown(ctx)
	_ = s.lis.Close() // never served: Shutdown does not own it
	return err
}

func (s *Server) reloadLoop() {
	t := time.NewTicker(s.o.ReloadInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			if err := s.reload(); err != nil && s.o.Logger != nil {
				s.o.Logger.Error("console certificate reload failed; keeping the current certificate", "err", err.Error())
			}
		}
	}
}

func (s *Server) reload() error {
	certPEM, err := os.ReadFile(s.o.CertFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return fmt.Errorf("console: cert: %w", err)
	}
	keyPEM, err := os.ReadFile(s.o.KeyFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return fmt.Errorf("console: key: %w", err)
	}
	sum := sha256.Sum256(append(append([]byte{}, certPEM...), keyPEM...))
	s.mu.Lock()
	defer s.mu.Unlock()
	if sum == s.hash {
		return nil
	}
	crt, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("console: certificate: %w", err)
	}
	s.cert.Store(&crt)
	s.hash = sum
	return nil
}

package console

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert writes a self-signed certificate for localhost with the given CN.
func writeCert(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	cf, kf := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cf+".tmp", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cf+".tmp", cf); err != nil {
		t.Fatal(err)
	}
	return cf, kf
}

func startServer(t *testing.T, o ServerOptions) *Server {
	t.Helper()
	s, err := NewServer(o, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- s.Start(context.Background()) }()
	t.Cleanup(func() {
		_ = s.Stop(context.Background())
		if err := <-errc; err != nil {
			t.Errorf("start returned %v", err)
		}
	})
	return s
}

func dialTLS(addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	return tls.DialWithDialer(d, "tcp", addr, cfg)
}

func TestServerTLS13HTTP1(t *testing.T) {
	cf, kf := writeCert(t, t.TempDir(), "first")
	s := startServer(t, ServerOptions{Addr: "127.0.0.1:0", CertFile: cf, KeyFile: kf, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	// TLS 1.2 is refused.
	if c, err := dialTLS(s.Addr(), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}); err == nil { //nolint:gosec // test
		c.Close()
		t.Fatal("TLS 1.2 accepted")
	}
	// TLS 1.3 offering h2 negotiates http/1.1 (WebSockets need it).
	c, err := dialTLS(s.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // test
	if err != nil {
		t.Fatal(err)
	}
	st := c.ConnectionState()
	c.Close()
	if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("version %x alpn %q", st.Version, st.NegotiatedProtocol)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}} //nolint:gosec // test
	resp, err := client.Get("https://" + s.Addr() + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "HTTP/1.1" {
		t.Fatalf("served over %q", body)
	}
}

func TestServerReloadsCertificate(t *testing.T) {
	dir := t.TempDir()
	cf, kf := writeCert(t, dir, "first")
	s := startServer(t, ServerOptions{Addr: "127.0.0.1:0", CertFile: cf, KeyFile: kf, ReloadInterval: 20 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	cn := func() string {
		c, err := dialTLS(s.Addr(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	if got := cn(); got != "first" {
		t.Fatalf("cn %q", got)
	}
	writeCert(t, dir, "second")
	deadline := time.Now().Add(5 * time.Second)
	for cn() != "second" {
		if time.Now().After(deadline) {
			t.Fatal("certificate not reloaded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A broken file keeps the current certificate.
	if err := os.WriteFile(cf, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := cn(); got != "second" {
		t.Fatalf("broken reload replaced the certificate: %q", got)
	}
}

func TestServerErrors(t *testing.T) {
	dir := t.TempDir()
	cf, kf := writeCert(t, dir, "x")
	h := http.NotFoundHandler()
	for name, o := range map[string]ServerOptions{
		"no cert":     {Addr: "127.0.0.1:0", KeyFile: kf},
		"missing":     {Addr: "127.0.0.1:0", CertFile: filepath.Join(dir, "nope.crt"), KeyFile: kf},
		"missing key": {Addr: "127.0.0.1:0", CertFile: cf, KeyFile: filepath.Join(dir, "nope.key")},
		"bad pair":    {Addr: "127.0.0.1:0", CertFile: kf, KeyFile: cf},
		"bad addr":    {Addr: "127.0.0.1:notaport", CertFile: cf, KeyFile: kf},
	} {
		if _, err := NewServer(o, h); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewServer(ServerOptions{Addr: "127.0.0.1:0", CertFile: cf, KeyFile: kf}, nil); err == nil {
		t.Error("nil handler accepted")
	}
	// Defaults.
	s, err := NewServer(ServerOptions{Addr: "127.0.0.1:0", CertFile: cf, KeyFile: kf}, h)
	if err != nil {
		t.Fatal(err)
	}
	if s.srv.ReadHeaderTimeout != 10*time.Second || s.srv.IdleTimeout != 60*time.Second || s.srv.MaxHeaderBytes != 8<<10 || s.o.ReloadInterval != time.Minute {
		t.Fatalf("defaults %+v", s.o)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start after stop: %v", err)
	}
	// A listener failure is reported.
	s2, err := NewServer(ServerOptions{Addr: "127.0.0.1:0", CertFile: cf, KeyFile: kf}, h)
	if err != nil {
		t.Fatal(err)
	}
	_ = s2.lis.Close()
	if err := s2.Start(context.Background()); err == nil {
		t.Fatal("closed listener: no error")
	}
	_ = s2.Stop(context.Background())
}

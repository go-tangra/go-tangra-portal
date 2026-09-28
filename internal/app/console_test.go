package app

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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/config"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	fconfig "github.com/go-tangra/go-tangra/v4/config"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

func certFiles(t *testing.T) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_ = os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return cf, kf
}

func consoleCfg(t *testing.T, enabled bool) config.Config {
	c := config.Default()
	c.PublicOrigin = "https://portal.example.org"
	c.Edge.Addr = "127.0.0.1:0"
	c.Edge.CertFile, c.Edge.KeyFile = certFiles(t)
	c.Console.Enabled = enabled
	c.Console.Addr = "127.0.0.1:0"
	c.Console.PublicOrigin = "https://portal.example.org:8444"
	return c
}

type noReg struct{}

func (noReg) State(string) registry.State                               { return "" }
func (noReg) Backends(string) (string, []registry.Instance)             { return "", nil }
func noTransport(string, fidentity.SPIFFEID) (http.RoundTripper, error) { return nil, nil }

// portalCSP serves one request on an edge built from cfg and returns its CSP.
func portalCSP(t *testing.T, cfg config.Config) string {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "gateway")
	ec := edgeConfig(cfg)
	ec.Env = "test"
	srv, err := edge.NewServer(rt, ec)
	if err != nil {
		t.Fatal(err)
	}
	srv.HandleFunc("/", func(http.ResponseWriter, *http.Request) {})
	t.Cleanup(testrt.StartServer(t, srv))
	ep, _ := srv.Endpoint()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test cert
	resp, err := client.Get("https://" + ep.Host + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Content-Security-Policy")
}

// The shell may frame the console origin only when the console is enabled;
// otherwise the portal policy has no frame-src at all (SC-003).
func TestEdgeFrameSourcesFollowConsole(t *testing.T) {
	if csp := portalCSP(t, consoleCfg(t, true)); !strings.Contains(csp, "frame-src 'self' https://portal.example.org:8444;") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("enabled: %q", csp)
	}
	if csp := portalCSP(t, consoleCfg(t, false)); strings.Contains(csp, "frame-src") {
		t.Fatalf("disabled: %q", csp)
	}
}

func TestNewConsole(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	lim := fconfig.Default().Limits
	if s, err := newConsole(consoleCfg(t, false), lim, noReg{}, noTransport, nil, log); s != nil || err != nil {
		t.Fatalf("disabled: %v %v", s, err)
	}
	s, err := newConsole(consoleCfg(t, true), lim, noReg{}, noTransport, nil, log)
	if err != nil || s == nil {
		t.Fatalf("enabled: %v", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- s.Start(context.Background()) }()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test cert
	resp, err := client.Get("https://" + s.Addr() + "/api/ipam/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors https://portal.example.org;") {
		t.Fatalf("console answered %d %v", resp.StatusCode, resp.Header)
	}
	resp, err = client.Get("https://" + s.Addr() + "/bmc/dev1/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unregistered ipam: %d", resp.StatusCode)
	}
	_ = s.Stop(context.Background())
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	// Invalid handler options surface as errors.
	bad := consoleCfg(t, true)
	bad.PublicOrigin = "not-an-origin"
	if _, err := newConsole(bad, lim, noReg{}, noTransport, nil, log); err == nil {
		t.Fatal("invalid portal origin accepted")
	}
}

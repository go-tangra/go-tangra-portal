//go:build integration

// Package integration boots the gateway, the auth module and test modules
// in-process against real TimescaleDB, Valkey (TLS), OpenFGA and Mailpit
// containers. Every service holds an SVID from one shared test CA.
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"

	"github.com/go-freya/freya"
	fconfig "github.com/go-freya/freya/config"
	"github.com/go-freya/freya/discovery"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/gateway/internal/app"
	"github.com/go-freya/freya/services/gateway/internal/config"
	"github.com/go-freya/freya/services/gateway/internal/store"
	"github.com/go-freya/freya/transport/edge"
)

const trustDomain = "example.org"

// captureLogger, when set by a test, receives the gateway's structured log.
var captureLogger slog.Handler

// Env is the running platform plus helpers.
type Env struct {
	T        *testing.T
	CA       *testutil.CA
	Gateway  *app.App
	Auth     *exec.Cmd
	AuthCfg  string // path of the auth configuration file (bootstrap uses it)
	AuthBin  string
	AuthLog  string
	Base     string // gateway edge: https://127.0.0.1:port
	AuthBase string // the auth module is reached through the gateway (gateway mode)
	AuthGRPC string // host:port of the auth Freya gRPC server
	GWGRPC   string // host:port of the gateway Freya gRPC server (registry)
	Mail     string
	Client   *http.Client
	Cancel   context.CancelFunc
	pgHost   string
	pgPort   string
	valkey   string
	valkeyCA string
}

func container(t *testing.T, req testcontainers.ContainerRequest) (host string, ports map[string]string) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Skipf("testcontainers unavailable (%s): %v", req.Image, err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ = c.Host(ctx)
	ports = map[string]string{}
	for _, p := range req.ExposedPorts {
		mp, err := c.MappedPort(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		ports[p] = mp.Port()
	}
	return host, ports
}

func selfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "valkey"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, DNSNames: []string{"localhost"}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	_ = os.WriteFile(certPath, pemBlock("CERTIFICATE", der), 0o644)
	_ = os.WriteFile(keyPath, pemBlock("EC PRIVATE KEY", kb), 0o644)
	return
}

func pemBlock(typ string, der []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(der)
	var buf bytes.Buffer
	buf.WriteString("-----BEGIN " + typ + "-----\n")
	for len(b64) > 64 {
		buf.WriteString(b64[:64] + "\n")
		b64 = b64[64:]
	}
	buf.WriteString(b64 + "\n-----END " + typ + "-----\n")
	return buf.Bytes()
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// Start boots every dependency, the auth module and the gateway; skips when Docker is absent.
func Start(t *testing.T) *Env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	ca := testutil.MustCA(trustDomain)
	pgHost, pgPorts := container(t, testcontainers.ContainerRequest{Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "auth"}, WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(2 * time.Minute)})
	adminAuth := fmt.Sprintf("postgres://postgres:test@%s:%s/auth?sslmode=disable", pgHost, pgPorts["5432/tcp"])
	adminGW := fmt.Sprintf("postgres://postgres:test@%s:%s/gateway?sslmode=disable", pgHost, pgPorts["5432/tcp"])
	for i := 0; i < 30; i++ {
		conn, err := pgx.Connect(ctx, adminAuth)
		if err == nil {
			_, _ = conn.Exec(ctx, "CREATE ROLE auth_app LOGIN PASSWORD 'app' NOBYPASSRLS")
			_, _ = conn.Exec(ctx, "CREATE ROLE gateway_app LOGIN PASSWORD 'app'")
			_, _ = conn.Exec(ctx, "CREATE DATABASE gateway")
			_ = conn.Close(ctx)
			break
		}
		time.Sleep(time.Second)
	}
	certPath, keyPath := selfSigned(t, dir)
	vkHost, vkPorts := container(t, testcontainers.ContainerRequest{Image: "valkey/valkey:8", ExposedPorts: []string{"6379/tcp"},
		Files:      []testcontainers.ContainerFile{{HostFilePath: certPath, ContainerFilePath: "/tls/server.crt", FileMode: 0o644}, {HostFilePath: keyPath, ContainerFilePath: "/tls/server.key", FileMode: 0o644}},
		Cmd:        []string{"valkey-server", "--tls-port", "6379", "--port", "0", "--tls-cert-file", "/tls/server.crt", "--tls-key-file", "/tls/server.key", "--tls-ca-cert-file", "/tls/server.crt", "--tls-auth-clients", "no", "--requirepass", "test"},
		WaitingFor: wait.ForListeningPort("6379/tcp")})
	fgaHost, fgaPorts := container(t, testcontainers.ContainerRequest{Image: "openfga/openfga:v1.20.0", ExposedPorts: []string{"8080/tcp"},
		Cmd: []string{"run", "--authn-method=preshared", "--authn-preshared-keys=test-key", "--playground-enabled=false"}, WaitingFor: wait.ForHTTP("/healthz").WithPort("8080/tcp")})
	mpHost, mpPorts := container(t, testcontainers.ContainerRequest{Image: "axllent/mailpit:latest", ExposedPorts: []string{"1025/tcp", "8025/tcp"}, WaitingFor: wait.ForListeningPort("8025/tcp")})

	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	kekPath := filepath.Join(dir, "kek.b64")
	_ = os.WriteFile(kekPath, []byte(base64.StdEncoding.EncodeToString(kek)), 0o600)
	authHTTP, authGRPC := freePort(t), freePort(t)
	gwEdge, gwGRPC := freePort(t), freePort(t)
	valkeyAddr := vkHost + ":" + vkPorts["6379/tcp"]

	// --- auth module: a separate process built from ../../../auth (its own edge
	// for sign-in until gateway mode lands in US2), identity from the shared CA.
	authBin := buildAuth(t)
	svidDir := filepath.Join(dir, "svid")
	authCert, authKey, bundle, err := ca.WriteSVID(svidDir, "auth", ca.MustIssue("auth", testutil.IssueOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	authCfg := filepath.Join(dir, "auth.yaml")
	authYAML := fmt.Sprintf(`service_name: auth
trust_domain: %s
env: test
identity:
  provider: file
  file: { cert: %s, key: %s, bundle: %s }
authz: { source: file, path: %s }
server: { grpc_addr: %s, http_addr: %s }
admin: { addr: 127.0.0.1:0 }
discovery:
  static:
    gateway: ["%s"]
gateway: { enabled: true, service: gateway }
issuer: https://%s
db:
  dsn: postgres://auth_app:app@%s:%s/auth?sslmode=disable
  migrate_dsn: %s
valkey: { addresses: ["%s"], password: test, ca_file: %s }
openfga: { url: http://%s:%s, preshared_key: test-key, allow_plaintext: true }
kek: { source: file, path: %s }
email: { transport: smtp, host: %s, port: %s, from: auth@example.org, allow_plaintext: true }
`, trustDomain, authCert, authKey, bundle, abs(t, "../../../auth/deploy/policy.yaml"), authGRPC, authHTTP, gwGRPC, gwEdge,
		pgHost, pgPorts["5432/tcp"], adminAuth, valkeyAddr, certPath, fgaHost, fgaPorts["8080/tcp"], kekPath, mpHost, mpPorts["1025/tcp"])
	if err := os.WriteFile(authCfg, []byte(authYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	authLog := filepath.Join(dir, "auth.log")

	// --- gateway
	gcfg := config.Default()
	gcfg.ServiceName, gcfg.TrustDomain, gcfg.Env = "gateway", trustDomain, "test"
	gcfg.Server.GRPCAddr, gcfg.Admin.Addr = gwGRPC, "127.0.0.1:0"
	gcfg.Authz = fconfig.Authz{Source: fconfig.AuthzFile, Path: "../../deploy/policy.yaml"}
	gcfg.PublicOrigin = "https://" + gwEdge
	gcfg.Edge.Addr = gwEdge
	gcfg.Edge.AllowedOrigins = []string{"https://" + gwEdge}
	gcfg.Edge.RateLimit = edge.RateLimit{PerSecond: 500, Burst: 1000}
	gcfg.DB.DSN = fmt.Sprintf("postgres://gateway_app:app@%s:%s/gateway?sslmode=disable", pgHost, pgPorts["5432/tcp"])
	gcfg.DB.MigrateDSN = adminGW
	gcfg.Valkey = config.Valkey{Addresses: []string{valkeyAddr}, Password: "test", CAFile: certPath}
	gcfg.Auth = config.Auth{Service: "auth", Issuer: "https://" + gwEdge, Audience: "gateway"}
	gcfg.Leases = config.Leases{TTL: 2 * time.Second, Renew: 500 * time.Millisecond}
	disc, err := discovery.NewStatic(map[string][]string{"auth": {authGRPC}})
	if err != nil {
		t.Fatal(err)
	}
	gwProv := testutil.NewMemProvider(ca, ca.MustIssue("gateway", testutil.IssueOptions{}))
	gw, err := app.Build(ctx, gcfg, app.Options{Migrate: true, Logger: captureLogger, Freya: []freya.Option{freya.WithIdentityProvider(gwProv), freya.WithDiscovery(disc)}})
	if err != nil {
		t.Fatalf("gateway build: %v", err)
	}

	// The auth module must be allowed before it starts registering.
	allowAuth := store.AllowEntry{ID: uuid.Must(uuid.NewV7()).String(), SpiffeID: "spiffe://" + trustDomain + "/svc/auth", Prefixes: []string{"/api/v1", "/authorize", "/.well-known", "/console"}, Names: []string{"auth"}, CreatedBy: "harness", CreatedAt: time.Now().UTC()}
	if err := gw.Store.Tx(ctx, func(tx pgx.Tx) error { return store.InsertAllow(ctx, tx, allowAuth) }); err != nil {
		t.Fatal(err)
	}
	authProc := startAuth(t, authBin, authCfg, authLog)
	runCtx, cancel := context.WithCancel(ctx)
	gwDone := make(chan error, 1)
	go func() { gwDone <- gw.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-gwDone:
		case <-time.After(15 * time.Second):
		}
		gw.Close()
	})
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}, //nolint:gosec // dev self-signed edge cert
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	env := &Env{T: t, CA: ca, Gateway: gw, Auth: authProc, AuthCfg: authCfg, AuthBin: authBin, AuthLog: authLog, Base: "https://" + gwEdge, AuthBase: "https://" + gwEdge, AuthGRPC: authGRPC, GWGRPC: gwGRPC,
		Mail: fmt.Sprintf("http://%s:%s", mpHost, mpPorts["8025/tcp"]), Client: client, Cancel: cancel,
		pgHost: pgHost, pgPort: pgPorts["5432/tcp"], valkey: valkeyAddr, valkeyCA: certPath}
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(authLog)
			if len(b) > 6000 {
				b = b[len(b)-6000:]
			}
			t.Logf("auth config:\n%s\nauth log tail:\n%s", authYAML, b)
		}
	})
	env.waitReady()
	return env
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func (e *Env) waitReady() {
	e.T.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if e.Gateway.Ready() {
			if resp, err := e.Client.Get(e.Base + "/gateway/v1/me"); err == nil {
				_ = resp.Body.Close()
				// The auth module answers through the gateway once registered (401 = auth reached, 404 = not yet),
				// and the gateway's own channel to auth works (a bogus cookie is refused, not "unavailable").
				if resp2, err := e.Client.Get(e.Base + "/api/v1/session"); err == nil {
					_ = resp2.Body.Close()
					if resp2.StatusCode == 401 {
						req, _ := http.NewRequest(http.MethodGet, e.Base+"/gateway/v1/me", nil)
						req.Header.Set("Cookie", "__Host-session=bogus")
						resp3, err := e.Client.Do(req)
						if err != nil {
							continue
						}
						_ = resp3.Body.Close()
						// ... and the token verifier has synced keys and revocations (a bogus bearer is refused, not "unavailable").
						req, _ = http.NewRequest(http.MethodGet, e.Base+"/gateway/v1/me", nil)
						req.Header.Set("Authorization", "Bearer bogus")
						resp4, err := e.Client.Do(req)
						if err != nil {
							continue
						}
						_ = resp4.Body.Close()
						if resp3.StatusCode == 401 && resp4.StatusCode == 401 {
							return
						}
					}
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	log, _ := os.ReadFile(e.AuthLog)
	e.T.Fatalf("platform did not become ready; auth log:\n%s", log)
}

var (
	buildOnce sync.Once
	builtAuth string
	buildErr  error
)

// buildAuth compiles the auth service once per test binary.
func buildAuth(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		out := filepath.Join(os.TempDir(), fmt.Sprintf("authsvc-%d", os.Getpid()))
		cmd := exec.Command("go", "build", "-o", out, "./cmd/authsvc")
		cmd.Dir = abs(t, "../../../auth")
		if b, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build authsvc: %v\n%s", err, b)
			return
		}
		builtAuth = out
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return builtAuth
}

func abs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// startAuth runs the auth service process; it is stopped with the test.
func startAuth(t *testing.T, bin, cfg, logPath string) *exec.Cmd {
	t.Helper()
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-config", cfg)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
		_ = logf.Close()
	})
	return cmd
}

// Bootstrap runs `authsvc bootstrap` and returns the platform tenant id and
// the invitation accept URL for the first operator.
func (e *Env) Bootstrap(operatorEmail string) (tenantID, acceptURL string) {
	e.T.Helper()
	cmd := exec.Command(e.AuthBin, "bootstrap", "-config", e.AuthCfg, "-operator-email", operatorEmail)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.T.Fatalf("bootstrap: %v: %s", err, out)
	}
	var res struct {
		TenantID  string `json:"tenant_id"`
		AcceptURL string `json:"accept_url"`
	}
	// The result is the last JSON document on stdout (logs precede it).
	if i := bytes.LastIndex(out, []byte("\n{\n")); i >= 0 {
		out = out[i+1:]
	}
	if err := json.Unmarshal(out, &res); err != nil {
		e.T.Fatalf("bootstrap output %q: %v", out, err)
	}
	return res.TenantID, res.AcceptURL
}

// AcceptOperator completes the bootstrap invitation on the auth edge and
// signs the operator in there; the session cookie lands in the shared jar.
func (e *Env) AcceptOperator(acceptURL, password string) {
	e.T.Helper()
	u, err := url.Parse(acceptURL)
	if err != nil {
		e.T.Fatal(err)
	}
	token := u.Query().Get("token")
	// Prime the CSRF cookie on the gateway origin.
	resp, err := e.Client.Get(e.Base + "/gateway/v1/me")
	if err != nil {
		e.T.Fatal(err)
	}
	_ = resp.Body.Close()
	if code, body := e.JSONAt(e.AuthBase, http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": token, "display_name": "Ops", "password": password}); code/100 != 2 {
		e.T.Fatalf("accept invitation → %d %v", code, body)
	}
}

// SignInAt signs in on the auth edge (tenant slug, email, password).
func (e *Env) SignInAt(slug, email, password string) (int, map[string]any) {
	e.T.Helper()
	resp, err := e.Client.Get(e.Base + "/gateway/v1/me")
	if err != nil {
		e.T.Fatal(err)
	}
	_ = resp.Body.Close()
	return e.JSONAt(e.AuthBase, http.MethodPost, "/api/v1/signin", map[string]string{"tenant": slug, "email": email, "password": password})
}

// SessionCookie returns the platform session cookie value from the jar.
func (e *Env) SessionCookie() string {
	u, _ := url.Parse(e.Base)
	for _, c := range e.Client.Jar.Cookies(u) {
		if c.Name == "__Host-session" {
			return c.Value
		}
	}
	return ""
}

// AuthLogContains reports whether the auth process log mentions s.
func (e *Env) AuthLogContains(s string) bool {
	b, _ := os.ReadFile(e.AuthLog)
	return strings.Contains(string(b), s)
}

// Allow seeds the gateway allow-list for a service identity.
func (e *Env) Allow(service string, prefixes, names []string) {
	e.T.Helper()
	entry := store.AllowEntry{ID: uuid.Must(uuid.NewV7()).String(), SpiffeID: "spiffe://" + trustDomain + "/svc/" + service, Prefixes: prefixes, Names: names, CreatedBy: "harness", CreatedAt: time.Now().UTC()}
	if err := e.Gateway.Store.Tx(context.Background(), func(tx pgx.Tx) error { return store.InsertAllow(context.Background(), tx, entry) }); err != nil {
		e.T.Fatal(err)
	}
}

// CSRF returns the double-submit token from the cookie jar for a base URL.
func (e *Env) CSRF(base string) string {
	u, _ := url.Parse(base)
	for _, c := range e.Client.Jar.Cookies(u) {
		if c.Name == edge.CSRFCookie {
			return c.Value
		}
	}
	return ""
}

// JSON performs a browser-style request against the gateway and decodes the body.
func (e *Env) JSON(method, path string, body any, hdr ...string) (int, map[string]any) {
	return e.JSONAt(e.Base, method, path, body, hdr...)
}

// JSONAt is JSON against an arbitrary base (the auth edge for sign-in).
func (e *Env) JSONAt(base, method, path string, body any, hdr ...string) (int, map[string]any) {
	e.T.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set(edge.CSRFHeader, e.CSRF(base))
		req.Header.Set("Origin", base)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.Client.Do(req)
	if err != nil {
		e.T.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// Module is a test module (a Freya service) reachable by the gateway.
type Module struct {
	Name       string
	App        *freya.App
	HTTPURL    string
	GRPCTarget string
	Cancel     context.CancelFunc
}

// StartModule boots a Freya service named name with an HTTP handler on its
// Freya HTTP server and optional gRPC services; it can dial the gateway by name.
func (e *Env) StartModule(name string, handler http.Handler, register func(grpc.ServiceRegistrar)) *Module {
	e.T.Helper()
	cfg := fconfig.Default()
	cfg.ServiceName, cfg.TrustDomain, cfg.Env = name, trustDomain, "test"
	cfg.Server.GRPCAddr, cfg.Server.HTTPAddr, cfg.Admin.Addr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	cfg.Authz = fconfig.Authz{Source: fconfig.AuthzFile, Path: "testdata/module-policy.yaml"}
	disc, err := discovery.NewStatic(map[string][]string{"gateway": {e.GWGRPC}, "auth": {e.AuthGRPC}})
	if err != nil {
		e.T.Fatal(err)
	}
	prov := testutil.NewMemProvider(e.CA, e.CA.MustIssue(name, testutil.IssueOptions{}))
	a, err := freya.New(cfg, freya.WithIdentityProvider(prov), freya.WithDiscovery(disc))
	if err != nil {
		e.T.Fatalf("module %s: %v", name, err)
	}
	if handler != nil {
		a.HTTP().HandlePrefix("/", handler)
	}
	if register != nil {
		register(a.GRPC())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	m := &Module{Name: name, App: a, Cancel: cancel}
	e.T.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		a.Close()
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if a.Ready() {
			if ep, err := a.HTTP().Endpoint(); err == nil {
				m.HTTPURL = "https://" + ep.Host
			}
			if ep, err := a.GRPC().Endpoint(); err == nil {
				m.GRPCTarget = ep.Host
			}
			if m.HTTPURL != "" && m.GRPCTarget != "" {
				return m
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.T.Fatalf("module %s did not become ready", name)
	return nil
}

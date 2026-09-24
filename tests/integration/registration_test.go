//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

func echoHandler(instance string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A fake federated remote under /ui/ (what the gateway relays at /m/<module>/).
		if strings.HasPrefix(r.URL.Path, "/ui/") {
			if strings.HasSuffix(r.URL.Path, "mf-manifest.json") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"` + instance + `","path":"` + r.URL.Path + `"}`))
				return
			}
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte("export const module = '" + instance + "';"))
			return
		}
		w.Header().Set("Set-Cookie", "leak=1")
		hdr := map[string]string{}
		for _, k := range []string{"X-Request-Id", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Gateway-Module", "Authorization", "Cookie", "X-Forwarded-For"} {
			hdr[k] = r.Header.Get(k)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"instance": instance, "path": r.URL.Path, "headers": hdr})
	})
}

func alphaManifest() gatewayclient.Manifest {
	return gatewayclient.Manifest{Module: "alpha", DisplayName: "Alpha", Version: "1.0.0", Prefixes: []string{"/api/alpha"},
		Routes:      []gatewayclient.Route{{Method: "GET", Path: "/api/alpha/ping", Public: true}, {Method: "GET", Path: "/api/alpha/secret", Permission: "alpha:read"}},
		Permissions: []gatewayclient.Permission{{Resource: "alpha", Action: "read"}}, Exposes: []string{"./routes"}}
}

// register runs the SDK loop for a module until the returned cancel is called.
func (e *Env) register(m *Module, man gatewayclient.Manifest) context.CancelFunc {
	e.T.Helper()
	conn, err := m.App.Client(context.Background(), "gateway")
	if err != nil {
		e.T.Fatal(err)
	}
	c, err := gatewayclient.New(conn, gatewayclient.Options{Manifest: man, HTTPURL: m.HTTPURL, GRPCTarget: m.GRPCTarget, InstanceID: m.Name + "-" + m.GRPCTarget})
	if err != nil {
		e.T.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	e.T.Cleanup(func() { cancel(); <-done })
	return func() { cancel(); <-done }
}

func (e *Env) waitStatus(path string, want int, within time.Duration) map[string]any {
	e.T.Helper()
	deadline := time.Now().Add(within)
	var code int
	var body map[string]any
	for time.Now().Before(deadline) {
		code, body = e.JSON(http.MethodGet, path, nil)
		if code == want {
			return body
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.T.Fatalf("%s → %d (want %d) %v", path, code, want, body)
	return nil
}

func (e *Env) auditCount(eventType, reason string) int {
	e.T.Helper()
	time.Sleep(1200 * time.Millisecond)
	var n int
	_ = e.Gateway.Store.Tx(context.Background(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM gateway_audit_events WHERE event_type = $1 AND ($2 = '' OR reason = $2)", eventType, reason).Scan(&n)
	})
	return n
}

func TestRegistrationLifecycle(t *testing.T) {
	e := Start(t)
	e.Allow("alpha", []string{"/api/alpha"}, []string{"alpha"})
	e.Allow("beta", []string{"/api/beta"}, []string{"beta"})
	alpha1 := e.StartModule("alpha", echoHandler("alpha-1"), nil)
	stop1 := e.register(alpha1, alphaManifest())

	// Public route reachable through the gateway with the forwarding header policy applied.
	body := e.waitStatus("/api/alpha/ping", 200, 10*time.Second)
	hdr := body["headers"].(map[string]any)
	if hdr["X-Request-Id"] == "" || hdr["X-Forwarded-Proto"] != "https" || hdr["X-Gateway-Module"] != "alpha" || hdr["Authorization"] != "" || hdr["Cookie"] != "" || hdr["X-Forwarded-For"] != "" {
		t.Fatalf("headers %v", hdr)
	}
	if !strings.HasPrefix(hdr["X-Forwarded-Host"].(string), "127.0.0.1:") {
		t.Fatalf("forwarded host %v", hdr["X-Forwarded-Host"])
	}
	resp, _ := e.Client.Get(e.Base + "/api/alpha/ping")
	if resp.Header.Get("Set-Cookie") != "" {
		t.Fatal("module Set-Cookie relayed")
	}
	_ = resp.Body.Close()
	if code, b := e.JSON(http.MethodGet, "/api/alpha/secret", nil); code != 401 || b["reason"] != "unauthenticated" {
		t.Fatalf("protected route → %d %v", code, b)
	}
	if code, b := e.JSON(http.MethodGet, "/api/alpha/other", nil); code != 404 || b["reason"] != "not_found" {
		t.Fatalf("undeclared route → %d %v", code, b)
	}
	if code, _ := e.JSON(http.MethodGet, "/api/nowhere", nil); code != 404 {
		t.Fatalf("unowned → %d", code)
	}

	// Two instances share the traffic.
	alpha2 := e.StartModule("alpha", echoHandler("alpha-2"), nil)
	stop2 := e.register(alpha2, alphaManifest())
	seen := map[string]bool{}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (!seen["alpha-1"] || !seen["alpha-2"]) {
		_, b := e.JSON(http.MethodGet, "/api/alpha/ping", nil)
		if inst, ok := b["instance"].(string); ok {
			seen[inst] = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !seen["alpha-1"] || !seen["alpha-2"] {
		t.Fatalf("load balancing %v", seen)
	}
	// Deregistering one instance keeps the module up; stopping the last withdraws it.
	stop2()
	time.Sleep(300 * time.Millisecond)
	e.waitStatus("/api/alpha/ping", 200, 5*time.Second)
	stop1()
	e.waitStatus("/api/alpha/ping", 404, 5*time.Second)
	// Restart re-registers within seconds.
	stopAgain := e.register(alpha1, alphaManifest())
	e.waitStatus("/api/alpha/ping", 200, 10*time.Second)
	stopAgain()

	// A crashed instance (no renewals, no deregister) is withdrawn once the lease expires.
	conn, _ := alpha1.App.Client(context.Background(), "gateway")
	pm, _ := alphaManifest().Proto()
	lease, err := gatewayv1.NewRegistryClient(conn).Register(context.Background(), &gatewayv1.RegisterRequest{Manifest: pm, InstanceId: "crash", Backend: &gatewayv1.Backend{HttpUrl: alpha1.HTTPURL}})
	if err != nil {
		t.Fatal(err)
	}
	e.waitStatus("/api/alpha/ping", 200, 5*time.Second)
	e.waitStatus("/api/alpha/ping", 404, 10*time.Second) // TTL is 2 s in the harness
	if _, err := gatewayv1.NewRegistryClient(conn).Renew(context.Background(), &gatewayv1.RenewRequest{LeaseId: lease.LeaseId}); status.Code(err) != codes.NotFound {
		t.Fatalf("expired lease renewable: %v", err)
	}
	if n := e.auditCount("registration_accepted", ""); n < 4 {
		t.Fatalf("registration_accepted audits %d", n)
	}
	if n := e.auditCount("registration_withdrawn", "lease_expired"); n != 1 {
		t.Fatalf("lease_expired audits %d", n)
	}
	if n := e.auditCount("registration_withdrawn", "deregistered"); n != 3 {
		t.Fatalf("deregistered audits %d", n)
	}
}

func TestPrefixHijackAndUnknownIdentity(t *testing.T) {
	e := Start(t)
	e.Allow("alpha", []string{"/api/alpha"}, []string{"alpha"})
	e.Allow("beta", []string{"/api/beta"}, []string{"beta"})
	alpha := e.StartModule("alpha", echoHandler("alpha"), nil)
	e.register(alpha, alphaManifest())
	e.waitStatus("/api/alpha/ping", 200, 10*time.Second)

	beta := e.StartModule("beta", echoHandler("beta"), nil)
	bconn, _ := beta.App.Client(context.Background(), "gateway")
	reg := gatewayv1.NewRegistryClient(bconn)
	// beta may not claim alpha's prefix: refused by the allow-list before any conflict check.
	hijack := gatewayclient.Manifest{Module: "beta", DisplayName: "Beta", Version: "1.0.0", Prefixes: []string{"/api/alpha"},
		Routes: []gatewayclient.Route{{Method: "GET", Path: "/api/alpha/ping", Public: true}}, Exposes: []string{"./routes"}}
	pm, _ := hijack.Proto()
	if _, err := reg.Register(context.Background(), &gatewayv1.RegisterRequest{Manifest: pm, InstanceId: "b1", Backend: &gatewayv1.Backend{HttpUrl: beta.HTTPURL}}); status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != "prefix_not_granted" {
		t.Fatalf("hijack: %v", err)
	}
	// beta may not use alpha's name either.
	pm2, _ := alphaManifest().Proto()
	if _, err := reg.Register(context.Background(), &gatewayv1.RegisterRequest{Manifest: pm2, InstanceId: "b1", Backend: &gatewayv1.Backend{HttpUrl: beta.HTTPURL}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("name hijack: %v", err)
	}
	// alpha keeps serving.
	if b := e.waitStatus("/api/alpha/ping", 200, 5*time.Second); b["instance"] != "alpha" {
		t.Fatalf("%v", b)
	}
	// An identity absent from the allow-list is refused.
	gamma := e.StartModule("gamma", echoHandler("gamma"), nil)
	gconn, _ := gamma.App.Client(context.Background(), "gateway")
	pm3, _ := (gatewayclient.Manifest{Module: "gamma", DisplayName: "Gamma", Version: "1.0.0", Prefixes: []string{"/api/gamma"}, Routes: []gatewayclient.Route{{Method: "GET", Path: "/api/gamma", Public: true}}, Exposes: []string{"./routes"}}).Proto()
	if _, err := gatewayv1.NewRegistryClient(gconn).Register(context.Background(), &gatewayv1.RegisterRequest{Manifest: pm3, InstanceId: "g1", Backend: &gatewayv1.Backend{HttpUrl: gamma.HTTPURL}}); status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != "identity_not_allowed" {
		t.Fatalf("unknown identity: %v", err)
	}
	if n := e.auditCount("registration_refused", ""); n != 3 {
		t.Fatalf("refusal audits %d", n)
	}
	// Allow-list entries are looked up live: revoking alpha's entry refuses its next registration.
	var id string
	_ = e.Gateway.Store.Tx(context.Background(), func(tx pgx.Tx) error {
		en, err := store.AllowBySpiffeID(context.Background(), tx, "spiffe://example.org/svc/alpha")
		id = en.ID
		return err
	})
	_ = e.Gateway.Store.Tx(context.Background(), func(tx pgx.Tx) error { return store.RevokeAllow(context.Background(), tx, id, time.Now()) })
	aconn, _ := alpha.App.Client(context.Background(), "gateway")
	if _, err := gatewayv1.NewRegistryClient(aconn).Register(context.Background(), &gatewayv1.RegisterRequest{Manifest: pm2, InstanceId: "a2", Backend: &gatewayv1.Backend{HttpUrl: alpha.HTTPURL}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked allow entry: %v", err)
	}
}

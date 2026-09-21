package health_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fidentity "github.com/go-freya/freya/identity"
	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/audit"
	"github.com/go-freya/freya/services/gateway/internal/health"
	"github.com/go-freya/freya/services/gateway/internal/httpapi"
	"github.com/go-freya/freya/services/gateway/internal/memstore"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

type stubBackend struct {
	target string
	status int
	hits   int
}

func (b *stubBackend) Target() string { return b.target }
func (b *stubBackend) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	b.hits++
	w.WriteHeader(b.status)
}

func TestCircuitStates(t *testing.T) {
	now := time.Unix(0, 0)
	c := &health.Circuit{Threshold: 3, Cooldown: 10 * time.Second}
	first, second := c.Observe(false, now), c.Observe(false, now)
	if first || second || c.Open() {
		t.Fatal("opened early")
	}
	if !c.Observe(false, now) || !c.Open() || c.ShouldProbe(now.Add(5*time.Second)) {
		t.Fatal("must open at the threshold and rest during the cool-down")
	}
	if !c.ShouldProbe(now.Add(10 * time.Second)) {
		t.Fatal("half-open after the cool-down")
	}
	// A failed half-open probe re-arms the cool-down without flipping.
	if c.Observe(false, now.Add(10*time.Second)) || c.ShouldProbe(now.Add(15*time.Second)) {
		t.Fatal("half-open failure")
	}
	if !c.Observe(true, now.Add(21*time.Second)) || c.Open() {
		t.Fatal("recovery must flip closed")
	}
	if c.Observe(true, now) {
		t.Fatal("success while closed is not a flip")
	}
}

// The dispatcher's failures open the breaker (after the threshold), the open
// state fails fast without touching the backend, a probe closes it again.
func TestCircuitThroughDispatcher(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms, Audit: aw})
	_, err := reg.Register(ctx, "spiffe://example.org/svc/orders", &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://i1"},
		Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
			Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/orders/ping", Public: true}}, Remote: &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	probeOK := false
	checker := health.New(health.Options{Registry: reg, Threshold: 3, Cooldown: 10 * time.Second, Now: func() time.Time { return now },
		Probe: func(context.Context, string, registry.Instance) error {
			if probeOK {
				return nil
			}
			return context.DeadlineExceeded
		}})
	be := &stubBackend{target: "https://i1", status: 504}
	d := &httpapi.Dispatcher{Reg: reg, Health: checker, Proxies: func(string, fidentity.SPIFFEID, string) (httpapi.Backend, error) { return be, nil }}
	call := func() int {
		w := httptest.NewRecorder()
		d.ServeHTTP(w, httptest.NewRequest("GET", "https://x/api/orders/ping", nil))
		return w.Code
	}
	// Three bounded failures (504) open the breaker; the fourth call fails fast with 503 and never reaches the backend.
	for i := 0; i < 3; i++ {
		if call() != 504 {
			t.Fatal("expected a bounded timeout answer")
		}
	}
	if reg.State("orders") != registry.StateUnhealthy || call() != 503 || be.hits != 3 {
		t.Fatalf("state=%s hits=%d", reg.State("orders"), be.hits)
	}
	// During the cool-down no probe runs; after it, a successful probe recovers the module.
	checker.Tick(ctx)
	if reg.State("orders") != registry.StateUnhealthy {
		t.Fatal("probed during cool-down")
	}
	now = now.Add(11 * time.Second)
	probeOK = true
	checker.Tick(ctx)
	be.status = 200
	if reg.State("orders") != registry.StateActive || call() != 200 {
		t.Fatalf("recovery: state=%s", reg.State("orders"))
	}
	aw.Close()
	unhealthy, recovered := 0, 0
	for _, r := range ms.Audit() {
		switch r.EventType {
		case "module_unhealthy":
			unhealthy++
		case "module_recovered":
			recovered++
		}
	}
	if unhealthy != 1 || recovered != 1 {
		t.Fatalf("audits unhealthy=%d recovered=%d", unhealthy, recovered)
	}
}

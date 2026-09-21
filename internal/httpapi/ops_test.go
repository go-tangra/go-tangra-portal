package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/audit"
	"github.com/go-freya/freya/services/gateway/internal/identity"
	"github.com/go-freya/freya/services/gateway/internal/memstore"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

type opsIdentity struct{}

func (opsIdentity) Resolve(_ context.Context, r *http.Request) (identity.Identity, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer operator":
		return identity.Identity{UserID: "op1", TenantID: "platform", Roles: []string{"owner", "operator"}, Operator: true, Token: "t"}, nil
	case "Bearer member":
		return identity.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"admin"}, Token: "t"}, nil
	case "Bearer platform-member":
		return identity.Identity{UserID: "u2", TenantID: "platform", Roles: []string{"member"}, Operator: true, Token: "t"}, nil
	}
	return identity.Identity{}, identity.ErrAnonymous
}

func opsServer(t *testing.T) (*Server, *registry.Registry, *memstore.Store, *Traffic) {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms, Audit: aw})
	_, err := reg.Register(ctx, "spiffe://example.org/svc/orders", &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://orders"},
		Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
			Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/orders", Public: true}}, Remote: &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}})
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTraffic()
	s := newTestServer(t)
	s.RegisterOps(OpsDeps{Reg: reg, Ops: &registry.Ops{Reg: reg, Marks: ms, Allow: ms, Audit: aw}, Identity: opsIdentity{}, Audit: ms, Traffic: tr, Roles: []string{"operator"}})
	return s, reg, ms, tr
}

func TestOpsAuthorization(t *testing.T) {
	s, _, _, _ := opsServer(t)
	for _, tc := range []struct {
		auth string
		code int
	}{{"", 401}, {"Bearer member", 403}, {"Bearer platform-member", 403}, {"Bearer operator", 200}} {
		hdr := map[string]string{}
		if tc.auth != "" {
			hdr["Authorization"] = tc.auth
		}
		if w := do(s, "GET", "/gateway/v1/ops/registrations", "", hdr); w.Code != tc.code {
			t.Errorf("%q → %d (want %d)", tc.auth, w.Code, tc.code)
		}
	}
	if !IsOperator(identity.Identity{Operator: true, Roles: []string{"operator"}}, []string{"operator"}) || IsOperator(identity.Identity{Operator: false, Roles: []string{"operator"}}, []string{"operator"}) {
		t.Fatal("IsOperator")
	}
}

func TestOpsRegistrationsAndControls(t *testing.T) {
	s, reg, ms, tr := opsServer(t)
	op := map[string]string{"Authorization": "Bearer operator", "X-CSRF-Token": "x"}
	tr.Record("orders", 200, 20*time.Millisecond)
	tr.Record("orders", 403, 5*time.Millisecond)
	w := do(s, "GET", "/gateway/v1/ops/registrations", "", op)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `"module":"orders"`) || !strings.Contains(body, `"state":"active"`) || !strings.Contains(body, `"requests_1m":2`) || !strings.Contains(body, `"refusals_1m":1`) || !strings.Contains(body, `"instances":1`) {
		t.Fatalf("%d %s", w.Code, body)
	}
	if w = do(s, "POST", "/gateway/v1/ops/registrations/orders/drain", "", op); w.Code != 204 {
		t.Fatalf("drain → %d %s", w.Code, w.Body.String())
	}
	if reg.State("orders") != registry.StateDraining {
		t.Fatal("not draining")
	}
	if w = do(s, "POST", "/gateway/v1/ops/registrations/ghost/drain", "", op); w.Code != 404 {
		t.Fatalf("drain ghost → %d", w.Code)
	}
	if w = do(s, "POST", "/gateway/v1/ops/registrations/orders/undrain", "", op); w.Code != 204 || reg.State("orders") != registry.StateActive {
		t.Fatalf("undrain → %d", w.Code)
	}
	if w = do(s, "POST", "/gateway/v1/ops/registrations/orders/revoke", `{"reason":"short"}`, op); w.Code != 400 {
		t.Fatalf("short reason → %d", w.Code)
	}
	if w = do(s, "POST", "/gateway/v1/ops/registrations/orders/revoke", `{"reason":"decommissioned by the platform team"}`, op); w.Code != 204 || reg.State("orders") != registry.StateRevoked {
		t.Fatalf("revoke → %d %s", w.Code, w.Body.String())
	}
	// Allow-list.
	w = do(s, "POST", "/gateway/v1/ops/allowlist", `{"spiffe_id":"spiffe://example.org/svc/billing","prefixes":["/api/billing/"],"names":["billing"]}`, op)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"prefixes":["/api/billing"]`) || !strings.Contains(w.Body.String(), `"created_by":"op1"`) {
		t.Fatalf("add → %d %s", w.Code, w.Body.String())
	}
	if w = do(s, "POST", "/gateway/v1/ops/allowlist", `{"spiffe_id":"spiffe://example.org/svc/billing","prefixes":["/x"],"names":["billing"]}`, op); w.Code != 400 {
		t.Fatalf("duplicate → %d", w.Code)
	}
	if w = do(s, "POST", "/gateway/v1/ops/allowlist", `{"spiffe_id":"nope","prefixes":["/x"],"names":["billing"]}`, op); w.Code != 400 {
		t.Fatalf("invalid → %d", w.Code)
	}
	w = do(s, "GET", "/gateway/v1/ops/allowlist", "", op)
	if w.Code != 200 || strings.Count(w.Body.String(), `"spiffe_id"`) != 2 {
		t.Fatalf("list → %d %s", w.Code, w.Body.String())
	}
	var id string
	for _, e := range ms.Allow {
		if e.SpiffeID == "spiffe://example.org/svc/billing" {
			id = e.ID
		}
	}
	if w = do(s, "POST", "/gateway/v1/ops/allowlist/"+id+"/revoke", "", op); w.Code != 204 {
		t.Fatalf("revoke allow → %d", w.Code)
	}
	if w = do(s, "POST", "/gateway/v1/ops/allowlist/"+id+"/revoke", "", op); w.Code != 404 {
		t.Fatalf("revoke twice → %d", w.Code)
	}
	// Audit trail (writer batches every 500 ms).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		w = do(s, "GET", "/gateway/v1/ops/audit?module=orders", "", op)
		if strings.Contains(w.Body.String(), "module_revoked") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"actor_id":"op1"`) || !strings.Contains(w.Body.String(), "module_drained") || !strings.Contains(w.Body.String(), "module_revoked") {
		t.Fatalf("audit → %d %s", w.Code, w.Body.String())
	}
	if w = do(s, "GET", "/gateway/v1/ops/audit?event_type=bogus", "", op); w.Code != 400 {
		t.Fatalf("bad type → %d", w.Code)
	}
	if w = do(s, "GET", "/gateway/v1/ops/audit?from=notatime", "", op); w.Code != 400 {
		t.Fatalf("bad time → %d", w.Code)
	}
	if w = do(s, "GET", "/gateway/v1/ops/audit?event_type=allowlist_changed&from=2020-01-01T00:00:00Z", "", op); w.Code != 200 || strings.Count(w.Body.String(), "allowlist_changed") < 2 {
		t.Fatalf("allow audits → %d %s", w.Code, w.Body.String())
	}
}

func TestTrafficCounters(t *testing.T) {
	tr := NewTraffic()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return now }
	tr.Record("", 200, time.Millisecond)
	for i := 0; i < 300; i++ {
		tr.Record("m", 200, time.Duration(i)*time.Millisecond)
	}
	tr.Record("m", 503, 500*time.Millisecond)
	s := tr.Snapshot("m")
	if s.Requests1m != 301 || s.Refusals1m != 1 || s.P95ms < 250 {
		t.Fatalf("%+v", s)
	}
	now = now.Add(2 * time.Minute)
	if s := tr.Snapshot("m"); s.Requests1m != 0 || s.P95ms == 0 {
		t.Fatalf("expired window: %+v", s)
	}
	if s := tr.Snapshot("unknown"); s.Requests1m != 0 {
		t.Fatal("unknown")
	}
	if b, _ := rawMessage(nil).MarshalJSON(); string(b) != "{}" {
		t.Fatal("raw")
	}
}

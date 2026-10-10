package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

var errStoreDown = errors.New("store down")

// catalogueServer: orders is registered (and recorded); billing and legacy
// are known but down, legacy not expected.
func catalogueServer(t *testing.T) (*Server, *registry.Registry, *memstore.Store, *audit.Writer) {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms, Audit: aw})
	if _, err := reg.Register(ctx, "spiffe://example.org/svc/orders", &gatewayv1.RegisterRequest{InstanceId: "i1", BuildVersion: "2.1.0", Backend: &gatewayv1.Backend{HttpUrl: "https://orders"},
		Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
			Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/orders", Public: true}}, Remote: &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	_ = ms.SeeKnown(ctx, store.KnownModule{Module: "orders", Identity: "spiffe://example.org/svc/orders", DisplayName: "Orders", LastVersion: "2.0.0", LastSeenAt: t0})
	_ = ms.SeeKnown(ctx, store.KnownModule{Module: "billing", Identity: "spiffe://example.org/svc/billing", DisplayName: "Billing", LastVersion: "1.4.2", LastSeenAt: t0.Add(time.Hour)})
	_ = ms.SeeKnown(ctx, store.KnownModule{Module: "legacy", Identity: "spiffe://example.org/svc/legacy", DisplayName: "Legacy", LastVersion: "0.9.0", LastSeenAt: t0})
	_ = ms.SetKnownExpected(ctx, "legacy", false)
	s := newTestServer(t)
	s.RegisterOps(OpsDeps{Reg: reg, Ops: &registry.Ops{Reg: reg, Marks: ms, Allow: ms, Audit: aw}, Identity: opsIdentity{}, Audit: ms, Roles: []string{"operator"},
		AdminRoles: []string{"owner", "admin"}, Known: ms, Events: aw})
	return s, reg, ms, aw
}

func catalogue(t *testing.T, s *Server, who string) (CatalogueView, int) {
	t.Helper()
	w := do(s, "GET", "/gateway/v1/ops/catalogue", "", map[string]string{"Authorization": "Bearer " + who})
	var v CatalogueView
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
	}
	return v, w.Code
}

// US1: the list merges the known record with the live registry.
func TestCatalogueListsRunningAndDownModules(t *testing.T) {
	s, reg, ms, _ := catalogueServer(t)
	v, code := catalogue(t, s, "operator")
	if code != 200 || !v.CanManage || len(v.Items) != 3 {
		t.Fatalf("%d %+v", code, v)
	}
	byName := map[string]CatalogueItem{}
	var order []string
	for _, it := range v.Items {
		byName[it.Module] = it
		order = append(order, it.Module)
	}
	if order[0] != "billing" || order[1] != "legacy" || order[2] != "orders" {
		t.Fatalf("not sorted: %v", order)
	}
	if o := byName["orders"]; o.State != "active" || !o.Registered || o.Instances != 1 || len(o.BuildVersions) != 1 || o.BuildVersions[0] != "2.1.0" || o.LastVersion != "2.0.0" || o.Identity != "spiffe://example.org/svc/orders" {
		t.Fatalf("orders %+v", o)
	}
	if b := byName["billing"]; b.State != "down" || b.Registered || b.Instances != 0 || b.LastVersion != "1.4.2" || b.LastSeenAt != "2026-10-09T11:00:00Z" || b.FirstSeenAt == "" || !b.Expected {
		t.Fatalf("billing %+v", b)
	}
	if l := byName["legacy"]; l.State != "stopped" || l.Expected {
		t.Fatalf("legacy %+v", l)
	}

	// Live states come from the registry; a revoked module is not "down".
	if err := (&registry.Ops{Reg: reg, Marks: ms}).Drain(context.Background(), "orders", registry.Operator{UserID: "op1"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := catalogue(t, s, "operator"); v.Items[2].State != "draining" {
		t.Fatalf("%+v", v.Items[2])
	}

	// An operator who is not an administrator reads it but may not manage it.
	if v, code := catalogue(t, s, "operator-only"); code != 200 || v.CanManage || len(v.Items) != 3 {
		t.Fatalf("%d %+v", code, v)
	}
}

// A module registered now but not yet recorded (store write pending or
// failed) is still listed from the live registry.
func TestCatalogueListsUnrecordedRegistrations(t *testing.T) {
	s, _, ms, _ := catalogueServer(t)
	delete(ms.Known, "orders")
	v, _ := catalogue(t, s, "operator")
	found := false
	for _, it := range v.Items {
		if it.Module == "orders" {
			found = it.State == "active" && it.Registered && it.DisplayName == "Orders" && it.Expected
		}
	}
	if !found {
		t.Fatalf("%+v", v.Items)
	}
}

// The store being down still shows what is registered; with nothing
// registered and no store, the answer is temporarily_unavailable.
func TestCatalogueStoreDown(t *testing.T) {
	s, _, ms, _ := catalogueServer(t)
	ms.Fail = errStoreDown
	v, code := catalogue(t, s, "operator")
	if code != 200 || len(v.Items) != 1 || v.Items[0].Module != "orders" || !v.Partial {
		t.Fatalf("%d %+v", code, v)
	}
}

func TestCatalogueReadAuthorization(t *testing.T) {
	s, _, _, _ := catalogueServer(t)
	for who, want := range map[string]int{"": 401, "member": 403, "platform-member": 403} {
		auth := map[string]string{}
		if who != "" {
			auth["Authorization"] = "Bearer " + who
		}
		if w := do(s, "GET", "/gateway/v1/ops/catalogue", "", auth); w.Code != want {
			t.Errorf("%q → %d, want %d", who, w.Code, want)
		}
	}
}

func auditTypes(aw *audit.Writer, ms *memstore.Store) map[string][]store.AuditRow {
	aw.Close()
	out := map[string][]store.AuditRow{}
	for _, r := range ms.Audit() {
		out[r.EventType] = append(out[r.EventType], r)
	}
	return out
}

func adminHdr(who string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + who, "X-CSRF-Token": "x"}
}

// US2: administrators say which modules should be running.
func TestCatalogueSetExpected(t *testing.T) {
	s, _, ms, aw := catalogueServer(t)
	if w := do(s, "PATCH", "/gateway/v1/ops/catalogue/billing", `{"expected":false}`, adminHdr("operator")); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	v, _ := catalogue(t, s, "operator")
	if v.Items[0].Module != "billing" || v.Items[0].State != "stopped" || v.Items[0].Expected {
		t.Fatalf("%+v", v.Items[0])
	}
	if w := do(s, "PATCH", "/gateway/v1/ops/catalogue/billing", `{"expected":true}`, adminHdr("operator")); w.Code != 204 {
		t.Fatal(w.Code)
	}
	// A running module may be marked too; its live state is still shown.
	if w := do(s, "PATCH", "/gateway/v1/ops/catalogue/orders", `{"expected":false}`, adminHdr("operator")); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if v, _ := catalogue(t, s, "operator"); v.Items[2].State != "active" || v.Items[2].Expected {
		t.Fatalf("%+v", v.Items[2])
	}
	ev := auditTypes(aw, ms)["known_module_expected"]
	if len(ev) != 3 || ev[0].Module != "billing" || ev[0].ActorID != "op1" || ev[0].ActorKind != "operator" || string(ev[0].Details) != `{"expected":false}` {
		t.Fatalf("%+v", ev)
	}
}

func TestCatalogueSetExpectedRefusals(t *testing.T) {
	s, _, ms, aw := catalogueServer(t)
	for _, tc := range []struct {
		name, who, path, body string
		want                  int
	}{
		{"operator without admin role", "operator-only", "billing", `{"expected":false}`, 403},
		{"platform member", "platform-member", "billing", `{"expected":false}`, 403},
		{"other tenant admin", "member", "billing", `{"expected":false}`, 403},
		{"bad module name", "operator", "Bad_Name", `{"expected":false}`, 400},
		{"extra field", "operator", "billing", `{"expected":false,"x":1}`, 400},
		{"not boolean", "operator", "billing", `{"expected":"no"}`, 400},
		{"missing field", "operator", "billing", `{}`, 400},
		{"unknown module", "operator", "nope", `{"expected":false}`, 404},
	} {
		if w := do(s, "PATCH", "/gateway/v1/ops/catalogue/"+tc.path, tc.body, adminHdr(tc.who)); w.Code != tc.want {
			t.Errorf("%s → %d %s, want %d", tc.name, w.Code, w.Body, tc.want)
		}
	}
	if k := ms.Known["billing"]; !k.Expected {
		t.Fatal("a refused request changed the store")
	}
	if w := do(s, "PATCH", "/gateway/v1/ops/catalogue/billing", `{"expected":false}`, nil); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	ms.Fail = errStoreDown
	w := do(s, "PATCH", "/gateway/v1/ops/catalogue/billing", `{"expected":false}`, adminHdr("operator"))
	if w.Code != 503 || w.Body.String() != "{\"reason\":\"temporarily_unavailable\"}\n" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	ms.Fail = nil
	refused := auditTypes(aw, ms)["permission_refused"]
	if len(refused) != 3 {
		t.Fatalf("refusals audited %d: %+v", len(refused), refused)
	}
	if len(auditTypes(aw, ms)["known_module_expected"]) != 0 {
		t.Fatal("refused changes audited as done")
	}
}

// US3: administrators forget a module that was removed for good.
func TestCatalogueForget(t *testing.T) {
	s, _, ms, aw := catalogueServer(t)
	if w := do(s, "DELETE", "/gateway/v1/ops/catalogue/billing", "", adminHdr("operator")); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	v, _ := catalogue(t, s, "operator")
	for _, it := range v.Items {
		if it.Module == "billing" {
			t.Fatal("forgotten module listed")
		}
	}
	for name, tc := range map[string]struct {
		who, module string
		want        int
	}{
		"registered module": {"operator", "orders", 409},
		"already forgotten": {"operator", "billing", 404},
		"unknown":           {"operator", "nope", 404},
		"not an admin":      {"operator-only", "legacy", 403},
		"bad module name":   {"operator", "-x", 400},
	} {
		if w := do(s, "DELETE", "/gateway/v1/ops/catalogue/"+tc.module, "", adminHdr(tc.who)); w.Code != tc.want {
			t.Errorf("%s → %d %s, want %d", name, w.Code, w.Body, tc.want)
		}
	}
	if _, ok := ms.Known["legacy"]; !ok || ms.Known["legacy"].ForgottenAt != nil {
		t.Fatal("refused forget changed the store")
	}
	ev := auditTypes(aw, ms)["known_module_forgotten"]
	if len(ev) != 1 || ev[0].Module != "billing" || ev[0].ActorID != "op1" {
		t.Fatalf("%+v", ev)
	}
	// Registering again makes a forgotten module known again (recorder path).
	_ = ms.SeeKnown(context.Background(), store.KnownModule{Module: "billing", Identity: "spiffe://example.org/svc/billing", DisplayName: "Billing", LastSeenAt: time.Now()})
	v, _ = catalogue(t, s, "operator")
	if v.Items[0].Module != "billing" || !v.Items[0].Expected {
		t.Fatalf("%+v", v.Items)
	}
}

package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/authz"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// scopedChecker grants by module:resource:action, like auth for 019.
type scopedChecker struct {
	allow map[string]bool
	asked []string
}

func (f *scopedChecker) BatchCheck(_ context.Context, in *authv1.BatchCheckRequest, _ ...grpc.CallOption) (*authv1.BatchCheckResponse, error) {
	resp := &authv1.BatchCheckResponse{}
	for _, p := range in.GetPermissions() {
		ref := p.GetModule() + ":" + p.GetResource() + ":" + p.GetAction()
		f.asked = append(f.asked, ref)
		resp.Results = append(resp.Results, &authv1.CheckResponse{Allowed: f.allow[ref], PolicyVersion: "v1"})
	}
	return resp, nil
}

// TestShellIsModuleScoped: warden and ticket both declare stats:read for
// their dashboards; a user holding warden's stats:read sees warden's nav and
// abilities only.
func TestShellIsModuleScoped(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms})
	for _, m := range []string{"warden", "ticket"} {
		_ = ms.InsertAllow(ctx, store.AllowEntry{ID: m, SpiffeID: "spiffe://example.org/svc/" + m, Prefixes: []string{"/api/" + m}, Names: []string{m}})
		_, err := reg.Register(ctx, "spiffe://example.org/svc/"+m, &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://" + m},
			Manifest: &gatewayv1.Manifest{Module: m, DisplayName: m, Version: "1.0.0", Prefixes: []string{"/api/" + m},
				Routes:      []*gatewayv1.Route{{Method: "GET", Path: "/api/" + m + "/stats", Permission: "stats:read"}},
				Permissions: []*gatewayv1.Permission{{Resource: "stats", Action: "read"}},
				Abilities:   []*gatewayv1.Ability{{Action: []string{"read"}, Subject: []string{m + "Stats"}, Requires: "stats:read"}},
				Nav:         []*gatewayv1.NavEntry{{Title: m + " dashboard", Path: "/" + m, Order: 1, Requires: "stats:read"}},
				Remote:      &gatewayv1.Remote{Entry: "/m/" + m + "/mf-manifest.json", Exposes: []string{"./routes"}}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	fc := &scopedChecker{allow: map[string]bool{"warden:stats:read": true}}
	dec, err := authz.New(authz.Options{Client: fc, KV: registry.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.RegisterShell(ShellDeps{Reg: reg, Identity: fakeIdentity{}, Decide: dec})
	auth := map[string]string{"Authorization": "Bearer ok"}

	w := do(s, "GET", "/gateway/v1/me/modules", "", auth)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var mods []ModuleView
	if err := json.Unmarshal(w.Body.Bytes(), &mods); err != nil || len(mods) != 2 {
		t.Fatalf("%v %s", err, w.Body.String())
	}
	for _, m := range mods {
		switch m.Module {
		case "warden":
			if len(m.Nav) != 1 || m.Nav[0].Title != "warden dashboard" {
				t.Fatalf("warden nav: %+v", m.Nav)
			}
		case "ticket":
			if len(m.Nav) != 0 {
				t.Fatalf("ticket nav unlocked by warden's stats:read: %+v", m.Nav)
			}
		}
	}

	w = do(s, "GET", "/gateway/v1/me/abilities", "", auth)
	var doc authz.AbilitiesDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); w.Code != 200 || err != nil {
		t.Fatalf("%d %v %s", w.Code, err, w.Body.String())
	}
	if len(doc.Modules) != 1 || len(doc.Modules["warden"]) != 1 || doc.Modules["ticket"] != nil {
		t.Fatalf("abilities bleed: %s", w.Body.String())
	}
	for _, a := range fc.asked {
		if a != "warden:stats:read" && a != "ticket:stats:read" {
			t.Fatalf("unqualified or foreign question %q", a)
		}
	}
}

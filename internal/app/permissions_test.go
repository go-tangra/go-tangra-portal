package app

import (
	"bytes"
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// fakeAuthz records RegisterPermissions calls; other methods are not used.
type fakeAuthz struct {
	authv1.AuthorizationClient
	mu     sync.Mutex
	reqs   []*authv1.RegisterPermissionsRequest
	reject map[string]codes.Code // module → error code
}

func (f *fakeAuthz) RegisterPermissions(_ context.Context, in *authv1.RegisterPermissionsRequest, _ ...grpc.CallOption) (*authv1.RegisterPermissionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, in)
	if c, ok := f.reject[in.GetModule()]; ok {
		return nil, status.Error(c, "rejected")
	}
	return &authv1.RegisterPermissionsResponse{Registered: uint32(len(in.GetPermissions()))}, nil
}

func (f *fakeAuthz) byModule() map[string]*authv1.RegisterPermissionsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]*authv1.RegisterPermissionsRequest{}
	for _, r := range f.reqs {
		out[r.GetModule()] = r
	}
	return out
}

func testApp(t *testing.T, fa *fakeAuthz, logs *bytes.Buffer) *App {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	reg, err := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms})
	if err != nil {
		t.Fatal(err)
	}
	mods := []struct{ name, display string }{{"warden", "Warden"}, {"ticket", "Helpdesk"}}
	for _, m := range mods {
		_ = ms.InsertAllow(ctx, store.AllowEntry{ID: m.name, SpiffeID: "spiffe://example.org/svc/" + m.name, Prefixes: []string{"/api/" + m.name}, Names: []string{m.name}})
		_, err := reg.Register(ctx, "spiffe://example.org/svc/"+m.name, &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://" + m.name},
			Manifest: &gatewayv1.Manifest{Module: m.name, DisplayName: m.display, Version: "1.0.0", Prefixes: []string{"/api/" + m.name},
				Routes:      []*gatewayv1.Route{{Method: "GET", Path: "/api/" + m.name + "/stats", Permission: "stats:read"}},
				Permissions: []*gatewayv1.Permission{{Resource: "stats", Action: "read", Description: "Read statistics"}, {Resource: m.name, Action: "admin"}},
				Remote:      &gatewayv1.Remote{Entry: "/m/" + m.name + "/mf-manifest.json", Exposes: []string{"./routes"}}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	return &App{Reg: reg, authz: fa, Log: slog.New(slog.NewTextHandler(logs, nil))}
}

// TestSyncPermissionsIsPerModule: each registration names its module and
// display name and carries only permissions — never roles, role sets or
// built-in grants (auth refuses those from the gateway).
func TestSyncPermissionsIsPerModule(t *testing.T) {
	fa := &fakeAuthz{}
	var logs bytes.Buffer
	a := testApp(t, fa, &logs)
	if err := a.SyncPermissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := fa.byModule()
	if len(fa.reqs) != 2 || len(got) != 2 {
		t.Fatalf("requests %v", fa.reqs)
	}
	for module, display := range map[string]string{"warden": "Warden", "ticket": "Helpdesk"} {
		r := got[module]
		if r == nil {
			t.Fatalf("no registration for %s", module)
		}
		if r.GetModuleDisplayName() != display {
			t.Fatalf("%s display name %q", module, r.GetModuleDisplayName())
		}
		if len(r.GetRoles()) != 0 || r.GetDeclaresRoles() || len(r.GetBuiltinGrants()) != 0 || len(r.GetTenantIds()) != 0 {
			t.Fatalf("%s: gateway sent roles/grants/tenants: %v", module, r)
		}
		var perms []string
		for _, p := range r.GetPermissions() {
			if strings.Contains(p.GetResource(), ":") || strings.Contains(p.GetAction(), ":") {
				t.Fatalf("qualified permission %v", p)
			}
			perms = append(perms, p.GetResource()+":"+p.GetAction())
		}
		sort.Strings(perms)
		want := []string{module + ":admin", "stats:read"}
		sort.Strings(want)
		if strings.Join(perms, ",") != strings.Join(want, ",") {
			t.Fatalf("%s permissions %v", module, perms)
		}
		if r.GetPermissions()[0].GetDescription() != "Read statistics" {
			t.Fatalf("description %v", r.GetPermissions()[0])
		}
	}
}

// TestSyncPermissionsContinuesAfterRejection: a refused registration (e.g.
// InvalidArgument from a newer auth) is logged and the other modules still
// register.
func TestSyncPermissionsContinuesAfterRejection(t *testing.T) {
	for _, c := range []codes.Code{codes.InvalidArgument, codes.PermissionDenied} {
		fa := &fakeAuthz{reject: map[string]codes.Code{"ticket": c, "warden": c}}
		var logs bytes.Buffer
		a := testApp(t, fa, &logs)
		err := a.SyncPermissions(context.Background())
		if status.Code(err) != c {
			t.Fatalf("%v: err %v", c, err)
		}
		if len(fa.reqs) != 2 {
			t.Fatalf("%v: stopped after the first rejection: %d", c, len(fa.reqs))
		}
		for _, m := range []string{"module=warden", "module=ticket"} {
			if !strings.Contains(logs.String(), m) {
				t.Fatalf("%v: rejection of %s not logged: %s", c, m, logs.String())
			}
		}
	}
	// Only one module refused: the other still registers.
	fa := &fakeAuthz{reject: map[string]codes.Code{"ticket": codes.InvalidArgument}}
	var logs bytes.Buffer
	a := testApp(t, fa, &logs)
	if err := a.SyncPermissions(context.Background()); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	if got := fa.byModule(); got["warden"] == nil || got["ticket"] == nil {
		t.Fatalf("%v", got)
	}
}

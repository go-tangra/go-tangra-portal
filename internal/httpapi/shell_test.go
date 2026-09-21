package httpapi

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	fidentity "github.com/go-freya/freya/identity"
	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/authz"
	"github.com/go-freya/freya/services/gateway/internal/identity"
	"github.com/go-freya/freya/services/gateway/internal/memstore"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

type fakeIdentity struct{}

func (fakeIdentity) Resolve(_ context.Context, r *http.Request) (identity.Identity, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer ok":
		return identity.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"member"}, Token: "ok"}, nil
	case "Bearer down":
		return identity.Identity{}, identity.ErrUnavailable
	}
	return identity.Identity{}, identity.ErrAnonymous
}

type fakeDecide struct {
	mu      sync.Mutex
	held    map[string]bool
	err     error
	version string
}

func (f *fakeDecide) setVersion(v string) { f.mu.Lock(); f.version = v; f.mu.Unlock() }

func (f *fakeDecide) Held(_ context.Context, _, _ string, perms []string) (map[string]bool, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]bool{}
	for _, p := range perms {
		if f.held[p] {
			out[p] = true
		}
	}
	return out, nil
}

func (f *fakeDecide) Abilities(ctx context.Context, regs []registry.Registration, tenant, user string, roles []string, v uint64) (authz.AbilitiesDoc, error) {
	if f.err != nil {
		return authz.AbilitiesDoc{}, f.err
	}
	doc := authz.AbilitiesDoc{Tenant: tenant, User: user, Roles: roles, Version: "x", Modules: map[string][]authz.PackedRule{}}
	for _, reg := range regs {
		for _, a := range reg.Manifest.Abilities {
			if f.held[a.Requires] {
				doc.Modules[reg.Module] = append(doc.Modules[reg.Module], authz.Pack(a))
			}
		}
	}
	return doc, nil
}

func (f *fakeDecide) TenantVersion(string) string { f.mu.Lock(); defer f.mu.Unlock(); return f.version }

func shellServer(t *testing.T) (*Server, *registry.Registry, *fakeDecide, *fakeBackend) {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "b", SpiffeID: "spiffe://example.org/svc/billing", Prefixes: []string{"/api/billing"}, Names: []string{"billing"}})
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms})
	for _, m := range []string{"orders", "billing"} {
		_, err := reg.Register(ctx, "spiffe://example.org/svc/"+m, &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://" + m},
			Manifest: &gatewayv1.Manifest{Module: m, DisplayName: strings.ToUpper(m), Version: "1.0.0", Prefixes: []string{"/api/" + m},
				Routes:      []*gatewayv1.Route{{Method: "GET", Path: "/api/" + m, Permission: m + ":read"}},
				Permissions: []*gatewayv1.Permission{{Resource: m, Action: "read"}, {Resource: m, Action: "admin"}},
				Abilities:   []*gatewayv1.Ability{{Action: []string{"read"}, Subject: []string{strings.ToUpper(m[:1]) + m[1:]}, Requires: m + ":read"}},
				Nav:         []*gatewayv1.NavEntry{{Title: m, Path: "/" + m, Order: 2, Requires: m + ":read"}, {Title: m + " admin", Path: "/" + m + "/admin", Order: 1, Requires: m + ":admin"}},
				Remote:      &gatewayv1.Remote{Entry: "/m/" + m + "/mf-manifest.json", Exposes: []string{"./routes"}}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	dec := &fakeDecide{held: map[string]bool{"orders:read": true}, version: "v1"}
	backend := &fakeBackend{target: "https://orders"}
	s := newTestServer(t)
	s.RegisterShell(ShellDeps{Reg: reg, Identity: fakeIdentity{}, Decide: dec, Proxies: func(module string, id fidentity.SPIFFEID, target string) (Backend, error) {
		if module == "billing" {
			return nil, errors.New("boom")
		}
		return backend, nil
	}})
	return s, reg, dec, backend
}

func TestModulesAndAbilities(t *testing.T) {
	s, reg, dec, _ := shellServer(t)
	if w := do(s, "GET", "/gateway/v1/me/modules", "", nil); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	if w := do(s, "GET", "/gateway/v1/me/modules", "", map[string]string{"Authorization": "Bearer down"}); w.Code != 503 {
		t.Fatalf("outage → %d", w.Code)
	}
	w := do(s, "GET", "/gateway/v1/me/modules", "", map[string]string{"Authorization": "Bearer ok"})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"module":"orders"`) || !strings.Contains(body, `"module":"billing"`) || !strings.Contains(body, `/m/orders/mf-manifest.json`) {
		t.Fatalf("%s", body)
	}
	// Navigation is filtered by held permissions (orders:read only) and ordered.
	if strings.Contains(body, "orders admin") || !strings.Contains(body, `"title":"orders"`) || strings.Contains(body, `"title":"billing"`) {
		t.Fatalf("nav filter: %s", body)
	}
	w = do(s, "GET", "/gateway/v1/me/abilities", "", map[string]string{"Authorization": "Bearer ok"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"orders":[["read","Orders"]]`) || strings.Contains(w.Body.String(), "Billing") || !strings.Contains(w.Body.String(), `"roles":["member"]`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Revoked modules disappear; decision outage → 503.
	reg.ApplyMark(context.Background(), "billing", "revoked")
	if w = do(s, "GET", "/gateway/v1/me/modules", "", map[string]string{"Authorization": "Bearer ok"}); strings.Contains(w.Body.String(), "billing") {
		t.Fatal("revoked module listed")
	}
	dec.err = errors.New("down")
	if w = do(s, "GET", "/gateway/v1/me/modules", "", map[string]string{"Authorization": "Bearer ok"}); w.Code != 503 {
		t.Fatalf("%d", w.Code)
	}
	if w = do(s, "GET", "/gateway/v1/me/abilities", "", map[string]string{"Authorization": "Bearer ok"}); w.Code != 503 {
		t.Fatalf("%d", w.Code)
	}
	if w = do(s, "GET", "/gateway/v1/me/abilities", "", nil); w.Code != 401 {
		t.Fatalf("%d", w.Code)
	}
}

func TestRemoteRelay(t *testing.T) {
	s, reg, _, backend := shellServer(t)
	w := do(s, "GET", "/m/orders/mf-manifest.json", "", nil)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || backend.hits != 1 {
		t.Fatalf("%d %v hits=%d", w.Code, w.Header(), backend.hits)
	}
	if !strings.Contains(w.Body.String(), "https://orders") {
		t.Fatalf("relayed to the wrong backend: %s", w.Body.String())
	}
	if w = do(s, "GET", "/m/orders/assets/index-WCNgJZ4r.js", "", nil); w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if w = do(s, "GET", "/m/orders/index.html", "", nil); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	// Traversal never reaches a backend: the mux redirects non-canonical paths, the relay refuses the rest.
	hits := backend.hits
	for _, bad := range []string{"/m/ghost/mf-manifest.json", "/m/orders/../secret", "/m/orders/a/../../etc/passwd", "/m/orders/%2e%2e/x", "/m/orders/%2e%2e%2fx"} {
		if w = do(s, "GET", bad, "", nil); w.Code != 404 && w.Code != 307 && w.Code != 301 {
			t.Errorf("%s → %d", bad, w.Code)
		}
	}
	if backend.hits != hits {
		t.Fatal("traversal reached the backend")
	}
	if w = do(s, "POST", "/m/orders/mf-manifest.json", "", nil); w.Code != 405 && w.Code != 404 {
		t.Fatalf("POST → %d", w.Code)
	}
	if w = do(s, "GET", "/m/billing/mf-manifest.json", "", nil); w.Code != 503 {
		t.Fatalf("proxy failure → %d", w.Code)
	}
	reg.ApplyMark(context.Background(), "orders", "revoked")
	if w = do(s, "GET", "/m/orders/mf-manifest.json", "", nil); w.Code != 404 {
		t.Fatalf("revoked remote → %d", w.Code)
	}
	reg.ApplyMark(context.Background(), "orders", "")
	reg.SetHealth(context.Background(), "orders", "i1", false)
	// Every instance unhealthy → temporarily unavailable, like API traffic.
	if w = do(s, "GET", "/m/orders/mf-manifest.json", "", nil); w.Code != 503 {
		t.Fatalf("%d", w.Code)
	}
	reg.SetHealth(context.Background(), "orders", "i1", true)
	backend.status = 500
	if w = do(s, "GET", "/m/orders/mf-manifest.json", "", nil); w.Code != 500 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	(&cacheWriter{ResponseWriter: httptest.NewRecorder()}).Flush()
}

func TestEventsStream(t *testing.T) {
	s, reg, dec, _ := shellServer(t)
	if w := do(s, "GET", "/gateway/v1/events", "", nil); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("GET", "https://localhost/gateway/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer ok")
	rec := newStreamRecorder()
	done := make(chan struct{})
	go func() { s.Handler().ServeHTTP(rec, req); close(done) }()
	time.Sleep(50 * time.Millisecond)
	reg.ApplyMark(context.Background(), "billing", "draining")
	dec.setVersion("v2")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out := rec.String()
		if strings.Contains(out, "event: registry") && strings.Contains(out, `"kind":"drained"`) && strings.Contains(out, "event: abilities") && strings.Contains(out, `"version":"v2"`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	out := rec.String()
	if !strings.Contains(out, "retry: 3000") || !strings.Contains(out, "event: registry") || !strings.Contains(out, "event: abilities") || rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%q", out)
	}
	for sc := bufio.NewScanner(strings.NewReader(out)); sc.Scan(); {
		if strings.HasPrefix(sc.Text(), "id: ") && sc.Text() == "id: 0" {
			t.Fatal("event without version")
		}
	}
}

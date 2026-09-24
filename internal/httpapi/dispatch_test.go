package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/httpproxy"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/route"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

type fakeBackend struct {
	target string
	hits   int
	mu     sync.Mutex
	status int
	sleep  time.Duration
}

func (f *fakeBackend) Target() string { return f.target }
func (f *fakeBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits++
	f.mu.Unlock()
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-r.Context().Done():
			w.WriteHeader(504)
			return
		}
	}
	if _, err := io.ReadAll(r.Body); err != nil {
		w.WriteHeader(413)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	_, _ = io.WriteString(w, f.target+" "+r.Header.Get("Authorization")+" addr="+httpproxy.ClientAddrFromContext(r.Context())+" hdr="+r.Header.Get(httpproxy.ClientAddrHeader))
}

type fakeAuth struct{ token string }

func (a fakeAuth) Authorize(r *http.Request, rt route.Route) (context.Context, *Error) {
	if r.Header.Get("Authorization") != "Bearer ok" {
		return nil, ErrUnauthenticated
	}
	if rt.Permission == "orders:admin" {
		return nil, ErrForbidden
	}
	r.Header.Set("Authorization", "Bearer "+a.token)
	return r.Context(), nil
}

type fakeHealth struct {
	mu   sync.Mutex
	seen []string
}

func (h *fakeHealth) Report(_ context.Context, m, i string, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen = append(h.seen, m+"/"+i+"="+map[bool]string{true: "ok", false: "fail"}[ok])
}

func newDispatcher(t *testing.T) (*Dispatcher, *registry.Registry, map[string]*fakeBackend, *fakeHealth) {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms})
	for _, inst := range []string{"i1", "i2"} {
		_, err := reg.Register(ctx, "spiffe://example.org/svc/orders", &gatewayv1.RegisterRequest{InstanceId: inst, Backend: &gatewayv1.Backend{HttpUrl: "https://" + inst},
			Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
				Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/orders/ping", Public: true}, {Method: "GET", Path: "/api/orders", Permission: "orders:read"},
					{Method: "DELETE", Path: "/api/orders/{id}", Permission: "orders:admin"}, {Method: "POST", Path: "/api/orders", Public: true, MaxBodyBytes: 8, Timeout: durationpb.New(50 * time.Millisecond)},
					{Method: "POST", Path: "/api/orders/open", Public: true, ClientAddress: true}},
				Permissions: []*gatewayv1.Permission{{Resource: "orders", Action: "read"}, {Resource: "orders", Action: "admin"}},
				Remote:      &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	backends := map[string]*fakeBackend{}
	health := &fakeHealth{}
	d := &Dispatcher{Reg: reg, Health: health, Limits: Limits{BodyBytes: 4, ModuleTimeout: time.Second},
		Proxies: func(module string, id identity.SPIFFEID, target string) (Backend, error) {
			if id.ServiceName() != "orders" || module != "orders" {
				t.Errorf("proxy for %s %s", module, id)
			}
			if target == "https://boom" {
				return nil, errors.New("boom")
			}
			b := &fakeBackend{target: target}
			backends[target] = b
			return b, nil
		},
		NotOwned: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }}
	return d, reg, backends, health
}

func serve(d *Dispatcher, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://platform"+path, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	return w
}

func TestDispatchRoutingStatesAndLimits(t *testing.T) {
	d, reg, backends, health := newDispatcher(t)
	// Public route round-robins across instances; the module never sees a client credential on public routes.
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		w := serve(d, "GET", "/api/orders/ping", "", map[string]string{"Authorization": "Bearer stolen"})
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		seen[strings.Fields(w.Body.String())[0]]++
	}
	if seen["https://i1"] != 2 || seen["https://i2"] != 2 || len(backends) != 2 {
		t.Fatalf("%v", seen)
	}
	// Unowned path → the shell fallback; owned prefix without a declared route → 404; bad path → 404.
	if w := serve(d, "GET", "/orders/42", "", nil); w.Code != 299 {
		t.Fatalf("fallback %d", w.Code)
	}
	if w := serve(d, "GET", "/api/orders/nope", "", nil); w.Code != 404 || !strings.Contains(w.Body.String(), "not_found") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := serve(d, "GET", "/api/orders/../x", "", nil); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
	// Protected route without an authorizer → 401; with one, 401/403/forwarded with the platform token.
	if w := serve(d, "GET", "/api/orders", "", nil); w.Code != 401 {
		t.Fatalf("%d", w.Code)
	}
	d.Auth = fakeAuth{token: "platform"}
	if w := serve(d, "GET", "/api/orders", "", nil); w.Code != 401 {
		t.Fatalf("%d", w.Code)
	}
	if w := serve(d, "DELETE", "/api/orders/1", "", map[string]string{"Authorization": "Bearer ok"}); w.Code != 403 {
		t.Fatalf("%d", w.Code)
	}
	if w := serve(d, "GET", "/api/orders", "", map[string]string{"Authorization": "Bearer ok"}); w.Code != 200 || !strings.Contains(w.Body.String(), "Bearer platform addr=") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Body limits: the route's own limit (8) wins over the default (4); over the limit → 413 audited.
	if w := serve(d, "POST", "/api/orders", "12345678", nil); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	if w := serve(d, "POST", "/api/orders", "123456789", nil); w.Code != 413 {
		t.Fatalf("%d", w.Code)
	}
	// Route timeout (50ms) cancels a slow backend → reported unhealthy observation.
	for _, b := range backends {
		b.sleep = 200 * time.Millisecond
	}
	if w := serve(d, "POST", "/api/orders", "", nil); w.Code != 504 {
		t.Fatalf("%d", w.Code)
	}
	for _, b := range backends {
		b.sleep = 0
	}
	health.mu.Lock()
	last := health.seen[len(health.seen)-1]
	health.mu.Unlock()
	if !strings.HasSuffix(last, "=fail") {
		t.Fatalf("%v", health.seen)
	}
	// Draining / unhealthy modules answer 503; no instances → 503.
	reg.ApplyMark(context.Background(), "orders", "draining")
	if w := serve(d, "GET", "/api/orders/ping", "", nil); w.Code != 503 || !strings.Contains(w.Body.String(), "temporarily_unavailable") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	reg.ApplyMark(context.Background(), "orders", "")
	reg.SetHealth(context.Background(), "orders", "i1", false)
	reg.SetHealth(context.Background(), "orders", "i2", false)
	if w := serve(d, "GET", "/api/orders/ping", "", nil); w.Code != 503 {
		t.Fatalf("%d", w.Code)
	}
	reg.SetHealth(context.Background(), "orders", "i1", true)
	reg.SetHealth(context.Background(), "orders", "i2", true)
	// Proxy construction failure → 503; Forget drops the cache.
	d.Forget("orders")
	d.Proxies = func(string, identity.SPIFFEID, string) (Backend, error) { return nil, errors.New("boom") }
	if w := serve(d, "GET", "/api/orders/ping", "", nil); w.Code != 503 {
		t.Fatalf("%d", w.Code)
	}
	d.Forget("other")
	// Flush passthrough.
	(&statusRecorder{ResponseWriter: httptest.NewRecorder()}).Flush()
}

func TestDispatchClientAddress(t *testing.T) {
	d, _, _, _ := newDispatcher(t)
	// Flagged route: the edge client address travels in the context; inbound copies are dropped.
	r := httptest.NewRequest("POST", "https://platform/api/orders/open", nil)
	r.Header.Set(httpproxy.ClientAddrHeader, "spoof")
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r.WithContext(edge.WithClientIP(r.Context(), "203.0.113.9")))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "addr=203.0.113.9 hdr=") || strings.Contains(w.Body.String(), "spoof") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Ordinary route: never.
	r = httptest.NewRequest("GET", "https://platform/api/orders/ping", nil)
	r.Header.Set(httpproxy.ClientAddrHeader, "spoof")
	w = httptest.NewRecorder()
	d.ServeHTTP(w, r.WithContext(edge.WithClientIP(r.Context(), "203.0.113.9")))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "addr= hdr=") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

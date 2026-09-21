package bind

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/authz"
	"github.com/go-freya/freya/services/gateway/internal/httpapi"
	"github.com/go-freya/freya/services/gateway/internal/identity"
	"github.com/go-freya/freya/services/gateway/internal/memstore"
	"github.com/go-freya/freya/services/gateway/internal/proxy/httpproxy"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/services/gateway/internal/route"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

type fakeResolver struct{ err error }

func (f fakeResolver) Resolve(_ context.Context, r *http.Request) (identity.Identity, error) {
	if f.err != nil {
		return identity.Identity{}, f.err
	}
	if r.Header.Get("Authorization") == "" {
		return identity.Identity{}, identity.ErrAnonymous
	}
	return identity.Identity{UserID: "u1", TenantID: "t1", SessionID: "s1", Token: "tok"}, nil
}
func (f fakeResolver) ResolveToken(_ context.Context, tok string) (identity.Identity, error) {
	if f.err != nil {
		return identity.Identity{}, f.err
	}
	if tok != "good" {
		return identity.Identity{}, identity.ErrUnauthenticated
	}
	return identity.Identity{UserID: "u1", TenantID: "t1", SessionID: "s1", Token: tok}, nil
}
func (f fakeResolver) ResolveSession(_ context.Context, c string) (identity.Identity, error) {
	if c != "cookie-good" {
		return identity.Identity{}, identity.ErrUnauthenticated
	}
	return identity.Identity{UserID: "u2", TenantID: "t1", SessionID: "s2", Token: "session-tok"}, nil
}

type fakeChecker struct {
	calls   int
	err     error
	version string
	allow   map[string]bool
}

func (f *fakeChecker) BatchCheck(_ context.Context, in *authv1.BatchCheckRequest, _ ...grpc.CallOption) (*authv1.BatchCheckResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	resp := &authv1.BatchCheckResponse{}
	for _, p := range in.Permissions {
		ref := p.Resource + ":" + p.Action
		resp.Results = append(resp.Results, &authv1.CheckResponse{Allowed: f.allow[ref], PolicyVersion: f.version, Reason: "no_permission"})
	}
	return resp, nil
}

func TestHTTPAuthorizer(t *testing.T) {
	fc := &fakeChecker{version: "v1", allow: map[string]bool{"orders:read": true}}
	d, _ := authz.New(authz.Options{Client: fc, KV: registry.NewMemory()})
	a := &HTTPAuthorizer{Identity: fakeResolver{}, Decider: d}
	rt := route.Route{Module: "orders", Permission: "orders:read"}
	if _, e := a.Authorize(httptest.NewRequest("GET", "/x", nil), rt); e != httpapi.ErrUnauthenticated {
		t.Fatalf("%v", e)
	}
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer good")
	ctx, e := a.Authorize(req, rt)
	if e != nil {
		t.Fatal(e)
	}
	if id, ok := identity.FromContext(ctx); !ok || id.UserID != "u1" {
		t.Fatal("identity missing from ctx")
	}
	if ctx.Value(httpproxy.WithToken(context.Background(), "x")) != nil {
		t.Fatal("unexpected")
	}
	if _, e := a.Authorize(req, route.Route{Module: "orders", Permission: "orders:write"}); e != httpapi.ErrForbidden {
		t.Fatalf("%v", e)
	}
	fc.err = errors.New("down")
	if _, e := a.Authorize(req, route.Route{Module: "orders", Permission: "orders:list"}); e != httpapi.ErrUnavailable {
		t.Fatalf("%v", e)
	}
	a.Identity = fakeResolver{err: identity.ErrUnavailable}
	if _, e := a.Authorize(req, rt); e != httpapi.ErrUnavailable {
		t.Fatalf("%v", e)
	}
	a.Identity = fakeResolver{err: errors.New("weird")}
	if _, e := a.Authorize(req, rt); e != httpapi.ErrUnavailable {
		t.Fatalf("%v", e)
	}
}

func TestDirector(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms})
	_, err := reg.Register(ctx, "spiffe://example.org/svc/orders", &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://i1", GrpcTarget: "i1:9443"},
		Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
			Methods:     []*gatewayv1.Method{{FullMethod: "/orders.v1.Orders/Get", Permission: "orders:read"}, {FullMethod: "/orders.v1.Orders/Ping", Public: true}, {FullMethod: "/orders.v1.Orders/Watch", Permission: "orders:read", Streaming: true}},
			Permissions: []*gatewayv1.Permission{{Resource: "orders", Action: "read"}}, Remote: &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}})
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeChecker{version: "v1", allow: map[string]bool{"orders:read": true}}
	dec, _ := authz.New(authz.Options{Client: fc, KV: registry.NewMemory()})
	d := &Director{Reg: reg, Identity: fakeResolver{}, Decider: dec, StreamMax: time.Hour, UnaryTimeout: 30 * time.Second}
	if _, err := d.Direct(ctx, "/nope.v1.X/Y", metadata.MD{}); status.Code(err) != codes.NotFound {
		t.Fatalf("%v", err)
	}
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Get", metadata.MD{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("%v", err)
	}
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Get", metadata.Pairs("authorization", "Bearer bad")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("%v", err)
	}
	r, err := d.Direct(ctx, "/orders.v1.Orders/Get", metadata.Pairs("authorization", "Bearer good"))
	if err != nil || r.Token != "good" || r.Target != "i1:9443" || r.Identity.ServiceName() != "orders" || r.MaxDuration != 30*time.Second || r.ClientKey != "t1/u1" || len(r.Subjects) != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	// Browser (grpc-web) calls authenticate with the session cookie.
	r, err = d.Direct(ctx, "/orders.v1.Orders/Watch", metadata.Pairs("cookie", "a=b; __Host-session=cookie-good; c=d"))
	if err != nil || r.Token != "session-tok" || r.MaxDuration != time.Hour {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Get", metadata.Pairs("cookie", "__Host-session=bad")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("%v", err)
	}
	// Public methods carry no token and no accounting key.
	r, err = d.Direct(ctx, "/orders.v1.Orders/Ping", metadata.MD{})
	if err != nil || r.Token != "" || r.ClientKey != "" {
		t.Fatalf("%+v %v", r, err)
	}
	// Permission denied and decision outage.
	fc.allow["orders:read"] = false
	fc.version = "v2"
	dec2, _ := authz.New(authz.Options{Client: fc, KV: registry.NewMemory()})
	d.Decider = dec2
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Get", metadata.Pairs("authorization", "Bearer good")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("%v", err)
	}
	fc.err = errors.New("down")
	dec3, _ := authz.New(authz.Options{Client: fc, KV: registry.NewMemory()})
	d.Decider = dec3
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Watch", metadata.Pairs("authorization", "Bearer good")); status.Code(err) != codes.Unavailable {
		t.Fatalf("%v", err)
	}
	d.Identity = fakeResolver{err: identity.ErrUnavailable}
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Get", metadata.Pairs("authorization", "Bearer good")); status.Code(err) != codes.Unavailable {
		t.Fatalf("%v", err)
	}
	// Draining / unhealthy → Unavailable.
	reg.ApplyMark(ctx, "orders", "draining")
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Ping", metadata.MD{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("%v", err)
	}
	reg.ApplyMark(ctx, "orders", "")
	reg.SetHealth(ctx, "orders", "i1", false)
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Ping", metadata.MD{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("%v", err)
	}
	// Instance without a gRPC backend.
	reg.SetHealth(ctx, "orders", "i1", true)
	_, _ = reg.Register(ctx, "spiffe://example.org/svc/orders", &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://i1"},
		Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.1.0", Prefixes: []string{"/api/orders"},
			Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/orders", Public: true}}, Remote: &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}})
	if _, err := d.Direct(ctx, "/orders.v1.Orders/Ping", metadata.MD{}); status.Code(err) != codes.NotFound {
		t.Fatalf("%v", err)
	}
	if parts := splitCookies(" a=1;; b=2 ;c"); len(parts) != 3 {
		t.Fatal(parts)
	}
	if _, _, ok := cutCookie("novalue"); ok {
		t.Fatal("cut")
	}
}

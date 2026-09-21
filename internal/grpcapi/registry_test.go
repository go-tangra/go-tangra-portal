package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya/authn"
	"github.com/go-freya/freya/identity"
	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/memstore"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

type watchStream struct {
	grpc.ServerStream
	ctx context.Context
	got []*gatewayv1.RegistryEvent
}

func (s *watchStream) Context() context.Context              { return s.ctx }
func (s *watchStream) Send(e *gatewayv1.RegistryEvent) error { s.got = append(s.got, e); return nil }

func peerCtx(name string) context.Context {
	id, _ := identity.NewSPIFFEID("example.org", name)
	return authn.WithPeer(context.Background(), authn.PeerIdentity{ID: id, ServiceName: name})
}

func TestRegistryServer(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms})
	s := &RegistryServer{Reg: reg}
	req := &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://127.0.0.1:1"},
		Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
			Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/orders", Public: true}}, Remote: &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}}
	// No verified peer → Unauthenticated on every method.
	if _, err := s.Register(ctx, req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no peer: %v", err)
	}
	if _, err := s.Renew(ctx, &gatewayv1.RenewRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("renew no peer")
	}
	if _, err := s.Deregister(ctx, &gatewayv1.DeregisterRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("deregister no peer")
	}
	if err := s.Watch(&gatewayv1.WatchRequest{}, &watchStream{ctx: ctx}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("watch no peer")
	}
	// Identity comes from the channel, not from the request.
	if _, err := s.Register(peerCtx("billing"), req); status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != registry.ReasonIdentityNotAllowed {
		t.Fatalf("foreign peer: %v", err)
	}
	lease, err := s.Register(peerCtx("orders"), req)
	if err != nil || lease.LeaseId == "" || lease.Module != "orders" || lease.Ttl.AsDuration() != 30*time.Second || lease.RenewEvery.AsDuration() != 10*time.Second {
		t.Fatalf("%v %v", lease, err)
	}
	if l2, err := s.Renew(peerCtx("orders"), &gatewayv1.RenewRequest{LeaseId: lease.LeaseId}); err != nil || l2.LeaseId != lease.LeaseId {
		t.Fatalf("%v %v", l2, err)
	}
	if _, err := s.Renew(peerCtx("orders"), &gatewayv1.RenewRequest{LeaseId: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown lease: %v", err)
	}
	// Watch replays from the cursor and streams live events.
	wctx, cancel := context.WithCancel(peerCtx("orders"))
	ws := &watchStream{ctx: wctx}
	done := make(chan error, 1)
	go func() { done <- s.Watch(&gatewayv1.WatchRequest{Cursor: "0"}, ws) }()
	time.Sleep(50 * time.Millisecond)
	if _, err := s.Deregister(peerCtx("orders"), &gatewayv1.DeregisterRequest{LeaseId: lease.LeaseId}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(ws.got) != 2 || ws.got[0].Kind != "registered" || ws.got[1].Kind != "withdrawn" || ws.got[1].Cursor == "" {
		t.Fatalf("%+v", ws.got)
	}
	if err := s.Watch(&gatewayv1.WatchRequest{Cursor: "abc"}, &watchStream{ctx: peerCtx("orders")}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad cursor: %v", err)
	}
	if _, err := s.Deregister(peerCtx("orders"), &gatewayv1.DeregisterRequest{LeaseId: lease.LeaseId}); status.Code(err) != codes.NotFound {
		t.Fatalf("double deregister: %v", err)
	}
	if toStatus(context.Canceled) == nil || status.Code(toStatus(context.Canceled)) != codes.Unavailable {
		t.Fatal("unknown error mapping")
	}
}

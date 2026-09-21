package gatewayclient

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"

	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
)

type fakeRegistry struct {
	gatewayv1.UnimplementedRegistryServer
	mu          sync.Mutex
	registers   int
	renews      int
	deregisters int
	refuse      error // returned by Register
	renewErr    error // returned by Renew
	last        *gatewayv1.RegisterRequest
}

func (f *fakeRegistry) Register(_ context.Context, r *gatewayv1.RegisterRequest) (*gatewayv1.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registers++
	f.last = r
	if f.refuse != nil {
		return nil, f.refuse
	}
	return &gatewayv1.Lease{LeaseId: "L1", Module: r.GetManifest().GetModule(), Ttl: durationpb.New(90 * time.Millisecond), RenewEvery: durationpb.New(30 * time.Millisecond), RegistryVersion: 1}, nil
}

func (f *fakeRegistry) Renew(_ context.Context, r *gatewayv1.RenewRequest) (*gatewayv1.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renews++
	if f.renewErr != nil {
		return nil, f.renewErr
	}
	return &gatewayv1.Lease{LeaseId: r.GetLeaseId(), Module: "orders", Ttl: durationpb.New(90 * time.Millisecond), RenewEvery: durationpb.New(30 * time.Millisecond), RegistryVersion: 2}, nil
}

func (f *fakeRegistry) Deregister(context.Context, *gatewayv1.DeregisterRequest) (*gatewayv1.DeregisterResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deregisters++
	return &gatewayv1.DeregisterResponse{}, nil
}

func (f *fakeRegistry) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registers, f.renews, f.deregisters
}

func dial(t *testing.T, f *fakeRegistry) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	gatewayv1.RegisterRegistryServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func manifest() Manifest {
	return Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
		Routes:      []Route{{Method: "GET", Path: "/api/orders", Permission: Perm("orders", "read"), Timeout: 5 * time.Second}, {Method: "GET", Path: "/api/orders/health", Public: true}},
		Methods:     []Method{{FullMethod: "/orders.v1.Orders/Watch", Permission: "orders:read", Streaming: true, MaxStreamDuration: time.Hour}},
		Permissions: []Permission{{Resource: "orders", Action: "read", Description: "Read"}},
		Abilities:   []Ability{{Action: []string{"read"}, Subject: []string{"Order"}, Conditions: map[string]any{"ownerId": map[string]any{"$eq": "${user.id}"}}, Requires: "orders:read"}},
		Exposes:     []string{"./routes"}, Nav: []NavEntry{{Title: "Orders", Path: "/orders", Order: 1, Requires: "orders:read"}}}
}

func TestManifestProto(t *testing.T) {
	pm, err := manifest().Proto()
	if err != nil || pm.Remote.Entry != "/m/orders/mf-manifest.json" || pm.Routes[0].Timeout.AsDuration() != 5*time.Second || pm.Routes[1].Timeout != nil ||
		pm.Methods[0].MaxStreamDuration.AsDuration() != time.Hour || pm.Abilities[0].Conditions.AsMap()["ownerId"] == nil || pm.Nav[0].Order != 1 {
		t.Fatalf("%v %v", pm, err)
	}
	if _, err := (Manifest{}).Proto(); err == nil {
		t.Fatal("empty module")
	}
	bad := manifest()
	bad.Abilities[0].Conditions = map[string]any{"x": make(chan int)}
	if _, err := bad.Proto(); err == nil {
		t.Fatal("unencodable conditions")
	}
}

func TestRegisterRenewDeregister(t *testing.T) {
	f := &fakeRegistry{}
	var states []State
	var mu sync.Mutex
	c, err := New(dial(t, f), Options{Manifest: manifest(), HTTPURL: "https://127.0.0.1:1", OnState: func(s State) { mu.Lock(); states = append(states, s); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, renews, _ := f.counts(); renews >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := c.State(); !st.Registered || st.LeaseID != "L1" || st.Version != 2 {
		t.Fatalf("%+v", st)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	regs, renews, deregs := f.counts()
	if regs != 1 || renews < 2 || deregs != 1 || c.State().Registered {
		t.Fatalf("registers=%d renews=%d deregisters=%d", regs, renews, deregs)
	}
	if f.last.GetInstanceId() == "" || f.last.GetBackend().GetHttpUrl() != "https://127.0.0.1:1" {
		t.Fatalf("%+v", f.last)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(states) < 2 || !states[0].Registered {
		t.Fatalf("%+v", states)
	}
}

func TestRefusalAndLeaseLoss(t *testing.T) {
	f := &fakeRegistry{refuse: status.Error(codes.PermissionDenied, "identity_not_allowed")}
	c, _ := New(dial(t, f), Options{Manifest: manifest(), GRPCTarget: "127.0.0.1:1", MaxBackoff: 20 * time.Millisecond})
	c.rand = func() float64 { return 0.5 }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if regs, _, _ := f.counts(); regs >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := c.State(); st.Registered || !errors.Is(st.Err, ErrRefused) {
		t.Fatalf("%+v", st)
	}
	// The gateway starts accepting, then drops the lease: the loop re-registers.
	f.mu.Lock()
	f.refuse = nil
	f.renewErr = status.Error(codes.NotFound, "unknown_lease")
	f.mu.Unlock()
	for time.Now().Before(deadline) {
		if regs, _, _ := f.counts(); regs >= 4 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	regs, renews, _ := f.counts()
	if regs < 4 || renews < 1 {
		t.Fatalf("registers=%d renews=%d", regs, renews)
	}
	cancel()
	<-done
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("nil conn")
	}
	conn := dial(t, &fakeRegistry{})
	if _, err := New(conn, Options{Manifest: Manifest{}}); err == nil {
		t.Fatal("empty manifest")
	}
	if _, err := New(conn, Options{Manifest: manifest()}); err == nil {
		t.Fatal("no backend")
	}
	c, err := New(conn, Options{Manifest: manifest(), HTTPURL: "https://x"})
	if err != nil || c.opts.InstanceID == "" || c.opts.MaxBackoff != 30*time.Second {
		t.Fatalf("%+v %v", c.opts, err)
	}
	if j := jitter(); j < 0 || j >= 1 {
		t.Fatal(j)
	}
	a, b := newInstanceID(), newInstanceID()
	if a == b || len(a) != 32 {
		t.Fatal("instance ids must differ")
	}
	bad := manifest()
	bad.Abilities[0].Conditions = map[string]any{"x": make(chan int)}
	c2, _ := New(conn, Options{Manifest: bad, HTTPURL: "https://x"})
	if err := c2.Run(context.Background()); err == nil {
		t.Fatal("unencodable manifest must fail Run")
	}
}

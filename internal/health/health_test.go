package health

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	tgrpc "github.com/go-tangra/go-tangra/v4/transport/grpc"
	thttp "github.com/go-tangra/go-tangra/v4/transport/http"
)

type fakeReg struct {
	mu     sync.Mutex
	regs   []registry.Registration
	states map[string]registry.State
	set    []string
}

func (f *fakeReg) Registrations() []registry.Registration { return f.regs }
func (f *fakeReg) State(m string) registry.State          { return f.states[m] }
func (f *fakeReg) SetHealth(_ context.Context, m, i string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set = append(f.set, m+"/"+i+"="+map[bool]string{true: "up", false: "down"}[ok])
}

func TestThresholdCooldownRecovery(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reg := &fakeReg{states: map[string]registry.State{"orders": registry.StateActive, "gone": registry.StateRevoked},
		regs: []registry.Registration{
			{Module: "orders", Identity: "spiffe://example.org/svc/orders", Instances: map[string]registry.Instance{"i1": {ID: "i1"}, "i2": {ID: "i2"}}},
			{Module: "gone", Identity: "spiffe://example.org/svc/gone", Instances: map[string]registry.Instance{"g1": {ID: "g1"}}},
		}}
	var mu sync.Mutex
	failing := map[string]bool{"i1": true}
	probes := 0
	c := New(Options{Registry: reg, Threshold: 3, Cooldown: 10 * time.Second, Now: func() time.Time { return now },
		Probe: func(_ context.Context, id string, in registry.Instance) error {
			mu.Lock()
			defer mu.Unlock()
			probes++
			if id != "spiffe://example.org/svc/orders" {
				t.Errorf("revoked module probed: %s", id)
			}
			if failing[in.ID] {
				return errors.New("down")
			}
			return nil
		}})
	if c.o.Interval != 5*time.Second || c.o.Timeout != 2*time.Second {
		t.Fatal("defaults")
	}
	c.Tick(ctx)
	c.Tick(ctx)
	if !c.Healthy("orders", "i1") || len(reg.set) != 0 {
		t.Fatalf("flipped before the threshold: %v", reg.set)
	}
	c.Tick(ctx)
	if c.Healthy("orders", "i1") || !c.Healthy("orders", "i2") || len(reg.set) != 1 || reg.set[0] != "orders/i1=down" {
		t.Fatalf("%v", reg.set)
	}
	// During the cool-down the unhealthy instance is not probed.
	mu.Lock()
	probes = 0
	mu.Unlock()
	now = now.Add(5 * time.Second)
	c.Tick(ctx)
	mu.Lock()
	if probes != 1 {
		t.Fatalf("probes during cooldown: %d", probes)
	}
	failing["i1"] = false
	mu.Unlock()
	// After the cool-down a successful probe recovers it.
	now = now.Add(6 * time.Second)
	c.Tick(ctx)
	if !c.Healthy("orders", "i1") || reg.set[len(reg.set)-1] != "orders/i1=up" {
		t.Fatalf("%v", reg.set)
	}
	// A failing probe while unhealthy extends the cool-down; traffic reports count too.
	c.Report(ctx, "orders", "i2", false)
	c.Report(ctx, "orders", "i2", false)
	c.Report(ctx, "orders", "i2", false)
	c.Report(ctx, "orders", "i2", false)
	if c.Healthy("orders", "i2") {
		t.Fatal("reports must reach the threshold")
	}
	c.Report(ctx, "orders", "i2", true)
	if !c.Healthy("orders", "i2") || c.Healthy("ghost", "x") != true {
		t.Fatal("recovery via traffic")
	}
	// Instances that left the registry are forgotten.
	reg.regs[0].Instances = map[string]registry.Instance{"i1": {ID: "i1"}}
	c.Tick(ctx)
	c.mu.Lock()
	_, kept := c.st["orders/i2"]
	c.mu.Unlock()
	if kept {
		t.Fatal("stale instance state kept")
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	c.o.Interval = 5 * time.Millisecond
	c.Run(rctx)
}

func TestDefaultProber(t *testing.T) {
	ca := testutil.MustCA("example.org")
	modRT := testrt.New(t, ca, "orders")
	hs, _ := thttp.NewServer(modRT, thttp.WithAddress("127.0.0.1:0"))
	hs.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	stopH := testrt.StartServer(t, hs)
	defer stopH()
	gs, _ := tgrpc.NewServer(modRT, tgrpc.WithAddress("127.0.0.1:0"))
	stopG := testrt.StartServer(t, gs)
	defer stopG()
	hep, _ := hs.Endpoint()
	gep, _ := gs.Endpoint()
	gw := testrt.New(t, ca, "gateway")
	probe := DefaultProber(gw)
	ctx := context.Background()
	id := "spiffe://example.org/svc/orders"
	if err := probe(ctx, id, registry.Instance{Backend: registry.Backend{HTTPURL: "https://" + hep.Host}}); err != nil {
		t.Fatalf("http probe: %v", err)
	}
	if err := probe(ctx, id, registry.Instance{Backend: registry.Backend{GRPCTarget: gep.Host}}); err != nil {
		t.Fatalf("grpc probe: %v", err)
	}
	if err := probe(ctx, "spiffe://example.org/svc/billing", registry.Instance{Backend: registry.Backend{HTTPURL: "https://" + hep.Host}}); err == nil {
		t.Fatal("wrong identity must fail the probe")
	}
	if err := probe(ctx, "spiffe://example.org/svc/billing", registry.Instance{Backend: registry.Backend{GRPCTarget: gep.Host}}); err == nil {
		t.Fatal("wrong identity must fail the grpc probe")
	}
	if err := probe(ctx, id, registry.Instance{Backend: registry.Backend{HTTPURL: "https://127.0.0.1:1"}}); err == nil {
		t.Fatal("dead backend")
	}
	if err := probe(ctx, id, registry.Instance{Backend: registry.Backend{GRPCTarget: "127.0.0.1:1"}}); err == nil {
		t.Fatal("dead grpc backend")
	}
	if err := probe(ctx, "not-a-spiffe-id", registry.Instance{}); err == nil {
		t.Fatal("bad identity")
	}
	if err := probe(ctx, "spiffe://other.org/svc/x", registry.Instance{Backend: registry.Backend{HTTPURL: "https://x"}}); err == nil {
		t.Fatal("foreign trust domain")
	}
	if err := probe(ctx, "spiffe://other.org/svc/x", registry.Instance{Backend: registry.Backend{GRPCTarget: "x:1"}}); err == nil {
		t.Fatal("foreign trust domain grpc")
	}
	if err := probe(ctx, id, registry.Instance{Backend: registry.Backend{HTTPURL: "https://[bad"}}); err == nil {
		t.Fatal("bad url")
	}
}

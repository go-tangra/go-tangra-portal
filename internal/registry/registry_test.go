package registry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/audit"
	"github.com/go-freya/freya/services/gateway/internal/memstore"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

const (
	idOrders  = "spiffe://example.org/svc/orders"
	idBilling = "spiffe://example.org/svc/billing"
	idGhost   = "spiffe://example.org/svc/ghost"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type harness struct {
	ctx context.Context
	kv  *Memory
	ms  *memstore.Store
	aw  *audit.Writer
	clk *clock
	reg *Registry
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	kv := NewMemory()
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	kv.Now = clk.now
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a1", SpiffeID: idOrders, Prefixes: []string{"/api/orders", "/orders-reports"}, Names: []string{"orders"}})
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a2", SpiffeID: idBilling, Prefixes: []string{"/api/billing", "/api"}, Names: []string{"billing"}})
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	reg, err := New(Options{KV: kv, Allow: ms, Marks: ms, Audit: aw, TTL: 30 * time.Second, Renew: 10 * time.Second, Now: clk.now, Origin: "gw-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Load(ctx); err != nil {
		t.Fatal(err)
	}
	return &harness{ctx: ctx, kv: kv, ms: ms, aw: aw, clk: clk, reg: reg}
}

func req(module, version, instance string, prefixes []string, routes ...*gatewayv1.Route) *gatewayv1.RegisterRequest {
	if routes == nil {
		routes = []*gatewayv1.Route{{Method: "GET", Path: strings.TrimSuffix(prefixes[0], "/") + "/ping", Public: true}}
	}
	cond, _ := structpb.NewStruct(map[string]any{"ownerId": map[string]any{"$eq": "${user.id}"}})
	return &gatewayv1.RegisterRequest{InstanceId: instance, Backend: &gatewayv1.Backend{HttpUrl: "https://127.0.0.1:1", GrpcTarget: "127.0.0.1:2"},
		Manifest: &gatewayv1.Manifest{Module: module, DisplayName: module, Version: version, Prefixes: prefixes, Routes: routes,
			Methods:     []*gatewayv1.Method{{FullMethod: "/" + module + ".v1.Svc/Get", Permission: module + ":read"}},
			Permissions: []*gatewayv1.Permission{{Resource: module, Action: "read"}},
			Abilities:   []*gatewayv1.Ability{{Action: []string{"read"}, Subject: []string{capital(module)}, Conditions: cond, Requires: module + ":read"}},
			Remote:      &gatewayv1.Remote{Entry: "/m/" + module + "/mf-manifest.json", Exposes: []string{"./routes"}},
			Nav:         []*gatewayv1.NavEntry{{Title: module, Path: "/" + module, Order: 1, Requires: module + ":read"}}}}
}

func capital(s string) string { return string(s[0]-32) + s[1:] }

func code(err error) codes.Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return codes.OK
}

func reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func (h *harness) auditCount(t *testing.T, typ audit.EventType, reason string) int {
	t.Helper()
	h.aw.Close()
	n := 0
	for _, r := range h.ms.Audit() {
		if r.EventType == string(typ) && (reason == "" || r.Reason == reason) {
			n++
		}
	}
	return n
}

func TestRegisterAcceptsAndRoutes(t *testing.T) {
	h := newHarness(t)
	lease, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i1", []string{"/api/orders/"}))
	if err != nil || lease.ID == "" || lease.Module != "orders" || lease.TTL != 30*time.Second || lease.Renew != 10*time.Second || lease.Version == 0 {
		t.Fatalf("%+v %v", lease, err)
	}
	if r, ok := h.reg.Table().Match("GET", "/api/orders/ping"); !ok || !r.Public || r.Module != "orders" {
		t.Fatalf("%+v %v", r, ok)
	}
	if id, be := h.reg.Backends("orders"); id != idOrders || len(be) != 1 || be[0].Backend.HTTPURL != "https://127.0.0.1:1" {
		t.Fatalf("%s %+v", id, be)
	}
	if h.reg.State("orders") != StateActive || h.reg.State("nope") != "" {
		t.Fatal("state")
	}
	got, ok := h.reg.Get("orders")
	if !ok || got.Manifest.Prefixes[0] != "/api/orders" || len(got.Instances) != 1 {
		t.Fatalf("%+v", got)
	}
	if _, ok := h.reg.Get("nope"); ok {
		t.Fatal("ghost")
	}
	if l := h.reg.Registrations(); len(l) != 1 || l[0].Module != "orders" {
		t.Fatal(l)
	}
	// Second instance with the identical manifest joins the module.
	l2, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i2", []string{"/api/orders"}))
	if err != nil || l2.ID == lease.ID {
		t.Fatalf("%+v %v", l2, err)
	}
	if _, be := h.reg.Backends("orders"); len(be) != 2 {
		t.Fatal(be)
	}
	// Re-registering the same instance replaces its lease.
	l3, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i2", []string{"/api/orders"}))
	if err != nil || l3.ID == l2.ID {
		t.Fatal(err)
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, l2.ID); code(err) != codes.NotFound {
		t.Fatalf("stale lease must be unknown: %v", err)
	}
	if n := h.auditCount(t, audit.RegistrationAccepted, ""); n != 3 {
		t.Fatalf("accepted audits %d", n)
	}
}

func TestRegisterRefusals(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name   string
		id     string
		req    *gatewayv1.RegisterRequest
		code   codes.Code
		reason string
	}{
		{"unknown identity", idGhost, req("ghost", "1.0.0", "i", []string{"/api/ghost"}), codes.PermissionDenied, ReasonIdentityNotAllowed},
		{"name not granted", idOrders, req("shipping", "1.0.0", "i", []string{"/api/orders"}), codes.PermissionDenied, ReasonNameNotGranted},
		{"prefix not granted", idOrders, req("orders", "1.0.0", "i", []string{"/api/ordersx"}), codes.PermissionDenied, ReasonPrefixNotGranted},
		{"invalid manifest", idOrders, &gatewayv1.RegisterRequest{InstanceId: "i", Manifest: &gatewayv1.Manifest{Module: "orders"}}, codes.InvalidArgument, ReasonManifestInvalid},
		{"nil manifest", idOrders, &gatewayv1.RegisterRequest{InstanceId: "i"}, codes.InvalidArgument, ReasonManifestInvalid},
		{"missing instance", idOrders, req("orders", "1.0.0", "", []string{"/api/orders"}), codes.InvalidArgument, ReasonManifestInvalid},
		{"http backend required", idOrders, func() *gatewayv1.RegisterRequest {
			r := req("orders", "1.0.0", "i", []string{"/api/orders"})
			r.Backend.HttpUrl = "http://plain"
			return r
		}(), codes.InvalidArgument, ReasonBackendRequired},
		{"grpc backend required", idOrders, func() *gatewayv1.RegisterRequest {
			r := req("orders", "1.0.0", "i", []string{"/api/orders"})
			r.Backend.GrpcTarget = ""
			return r
		}(), codes.InvalidArgument, ReasonBackendRequired},
	}
	for _, c := range cases {
		_, err := h.reg.Register(h.ctx, c.id, c.req)
		if code(err) != c.code || reason(err) != c.reason {
			t.Errorf("%s: %v (want %s/%s)", c.name, err, c.code, c.reason)
		}
	}
	if h.reg.Table().RemoteState("orders") != "" {
		t.Fatal("refused module must not be routable")
	}
	if n := h.auditCount(t, audit.RegistrationRefused, ""); n != len(cases) {
		t.Fatalf("refusal audits %d", n)
	}
}

func TestConflictsDriftAndVersionBump(t *testing.T) {
	h := newHarness(t)
	if _, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i1", []string{"/api/orders"})); err != nil {
		t.Fatal(err)
	}
	// Billing is allowed "/api" but orders already owns "/api/orders": overlap refused.
	if _, err := h.reg.Register(h.ctx, idBilling, req("billing", "1.0.0", "b1", []string{"/api"})); reason(err) != ReasonPrefixConflict || code(err) != codes.AlreadyExists {
		t.Fatalf("hijack accepted: %v", err)
	}
	// CASL subject collision across modules is refused.
	dup := req("billing", "1.0.0", "b1", []string{"/api/billing"})
	dup.Manifest.Abilities[0].Subject = []string{"Orders"}
	if _, err := h.reg.Register(h.ctx, idBilling, dup); reason(err) != ReasonSubjectConflict {
		t.Fatalf("subject collision accepted: %v", err)
	}
	// Another identity cannot join an existing module even if allowed the name.
	_ = h.ms.InsertAllow(h.ctx, store.AllowEntry{ID: "a3", SpiffeID: idGhost, Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	if _, err := h.reg.Register(h.ctx, idGhost, req("orders", "1.0.0", "g1", []string{"/api/orders"})); reason(err) != ReasonIdentityMismatch {
		t.Fatalf("identity mismatch accepted: %v", err)
	}
	// Same version, different content → drift.
	drift := req("orders", "1.0.0", "i2", []string{"/api/orders"}, &gatewayv1.Route{Method: "GET", Path: "/api/orders/other", Public: true})
	if _, err := h.reg.Register(h.ctx, idOrders, drift); reason(err) != ReasonManifestDrift || code(err) != codes.FailedPrecondition {
		t.Fatalf("drift accepted: %v", err)
	}
	// Lower version → drift too.
	if _, err := h.reg.Register(h.ctx, idOrders, req("orders", "0.9.0", "i2", []string{"/api/orders"}, &gatewayv1.Route{Method: "GET", Path: "/api/orders/old", Public: true})); reason(err) != ReasonManifestDrift {
		t.Fatalf("downgrade accepted: %v", err)
	}
	// Version bump replaces the manifest atomically; the old instance's renewal is refused.
	l1, _ := h.reg.Get("orders")
	oldLease := l1.Instances["i1"].LeaseID
	l2, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.1.0", "i2", []string{"/api/orders"}, &gatewayv1.Route{Method: "GET", Path: "/api/orders/v2", Public: true}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.reg.Table().Match("GET", "/api/orders/v2"); !ok {
		t.Fatal("new manifest not routable")
	}
	if _, ok := h.reg.Table().Match("GET", "/api/orders/ping"); ok {
		t.Fatal("old manifest still routable")
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, oldLease); reason(err) != ReasonManifestDrift {
		t.Fatalf("old instance renewal: %v", err)
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, l2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.Renew(h.ctx, idBilling, l2.ID); reason(err) != ReasonIdentityMismatch {
		t.Fatalf("foreign renewal: %v", err)
	}
	if n := h.auditCount(t, audit.RegistrationUpdated, ""); n != 1 {
		t.Fatalf("updated audits %d", n)
	}
	if n := h.auditCount(t, audit.RenewalRefused, ""); n != 2 {
		t.Fatalf("renewal refusals %d", n)
	}
}

func TestLeaseExpiryDeregisterAndWatch(t *testing.T) {
	h := newHarness(t)
	events, stop := h.reg.Watch(0)
	defer stop()
	l1, _ := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i1", []string{"/api/orders"}))
	l2, _ := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i2", []string{"/api/orders"}))
	// Renewals keep i1 alive; i2 stops renewing and is withdrawn after the TTL.
	for i := 0; i < 4; i++ {
		h.clk.t = h.clk.t.Add(10 * time.Second)
		if _, err := h.reg.Renew(h.ctx, idOrders, l1.ID); err != nil {
			t.Fatal(err)
		}
		h.reg.Sweep(h.ctx)
	}
	if _, be := h.reg.Backends("orders"); len(be) != 1 || be[0].ID != "i1" {
		t.Fatalf("expired instance still present: %+v", be)
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, l2.ID); code(err) != codes.NotFound {
		t.Fatalf("expired lease renewable: %v", err)
	}
	// Deregister the last instance: the module and its routes disappear.
	if err := h.reg.Deregister(h.ctx, idBilling, l1.ID); code(err) != codes.NotFound {
		t.Fatalf("foreign deregister: %v", err)
	}
	if err := h.reg.Deregister(h.ctx, idOrders, l1.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.reg.Deregister(h.ctx, idOrders, l1.ID); code(err) != codes.NotFound {
		t.Fatal("double deregister")
	}
	if _, ok := h.reg.Table().Match("GET", "/api/orders/ping"); ok {
		t.Fatal("withdrawn module still routable")
	}
	if _, ok := h.reg.Get("orders"); ok {
		t.Fatal("withdrawn module still known")
	}
	if _, ok, _ := h.kv.Get(h.ctx, regKey("orders")); ok {
		t.Fatal("kv still holds the registration")
	}
	var kinds []string
	timeout := time.After(time.Second)
	for len(kinds) < 4 {
		select {
		case ev := <-events:
			kinds = append(kinds, ev.Kind)
		case <-timeout:
			t.Fatalf("events %v", kinds)
		}
	}
	if kinds[0] != EventRegistered || kinds[1] != EventUpdated || kinds[2] != EventUpdated || kinds[3] != EventWithdrawn {
		t.Fatal(kinds)
	}
	if n := h.auditCount(t, audit.RegistrationWithdrawn, "lease_expired"); n != 1 {
		t.Fatalf("expiry audits %d", n)
	}
	if n := h.auditCount(t, audit.RegistrationWithdrawn, "deregistered"); n != 1 {
		t.Fatalf("deregister audits %d", n)
	}
	// Replay from a cursor, then a slow consumer is closed on overflow.
	replay, stop2 := h.reg.Watch(1)
	defer stop2()
	if ev := <-replay; ev.Version != 2 {
		t.Fatalf("replay %+v", ev)
	}
	slow, stop3 := h.reg.Watch(h.reg.Version())
	for i := 0; i < 70; i++ {
		h.reg.fanout(Event{Kind: EventUpdated, Module: "x", Version: h.reg.Version() + uint64(i) + 1})
	}
	n := 0
	for range slow {
		n++
	}
	if n != 64 {
		t.Fatalf("slow watcher got %d before close", n)
	}
	stop3()
}

func TestMarksHealthAndState(t *testing.T) {
	h := newHarness(t)
	l1, _ := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i1", []string{"/api/orders"}))
	_, _ = h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i2", []string{"/api/orders"}))
	// Health: one bad instance keeps the module active; both → unhealthy; recovery flips back.
	h.reg.SetHealth(h.ctx, "orders", "i1", false)
	if h.reg.State("orders") != StateActive {
		t.Fatal("one unhealthy instance must not degrade the module")
	}
	if _, be := h.reg.Backends("orders"); len(be) != 1 || be[0].ID != "i2" {
		t.Fatalf("%+v", be)
	}
	h.reg.SetHealth(h.ctx, "orders", "i2", false)
	h.reg.SetHealth(h.ctx, "orders", "i2", false) // idempotent
	if h.reg.State("orders") != StateUnhealthy {
		t.Fatal("module must be unhealthy")
	}
	if r, ok := h.reg.Table().Match("GET", "/api/orders/ping"); !ok || r.State != "unhealthy" {
		t.Fatalf("%+v", r)
	}
	h.reg.SetHealth(h.ctx, "orders", "i1", true)
	if h.reg.State("orders") != StateActive {
		t.Fatal("recovery")
	}
	h.reg.SetHealth(h.ctx, "orders", "ghost", false)
	h.reg.SetHealth(h.ctx, "ghost", "i1", false)
	// Draining: renewals and new registrations refused, routes marked.
	h.reg.ApplyMark(h.ctx, "orders", "draining")
	if h.reg.State("orders") != StateDraining {
		t.Fatal("draining")
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, l1.ID); reason(err) != ReasonModuleDraining {
		t.Fatalf("renew while draining: %v", err)
	}
	if _, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i3", []string{"/api/orders"})); reason(err) != ReasonModuleDraining {
		t.Fatalf("register while draining: %v", err)
	}
	if r, ok := h.reg.Table().Match("GET", "/api/orders/ping"); !ok || r.State != "draining" {
		t.Fatalf("%+v", r)
	}
	h.reg.ApplyMark(h.ctx, "orders", "")
	if _, err := h.reg.Renew(h.ctx, idOrders, l1.ID); err != nil {
		t.Fatal(err)
	}
	// Revoked (via the durable store + refresh): routes vanish, renew refused.
	_ = h.ms.SetMark(h.ctx, store.Mark{ID: "m1", Module: "orders", Mark: "revoked"})
	if err := h.reg.RefreshMarks(h.ctx); err != nil {
		t.Fatal(err)
	}
	if h.reg.State("orders") != StateRevoked {
		t.Fatal("revoked")
	}
	if _, ok := h.reg.Table().Match("GET", "/api/orders/ping"); ok {
		t.Fatal("revoked module routable")
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, l1.ID); reason(err) != ReasonModuleRevoked {
		t.Fatalf("renew while revoked: %v", err)
	}
	if _, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i3", []string{"/api/orders"})); reason(err) != ReasonModuleRevoked {
		t.Fatalf("register while revoked: %v", err)
	}
	if h.auditCount(t, audit.ModuleUnhealthy, "") != 1 || h.auditCount(t, audit.ModuleRecovered, "") != 1 {
		t.Fatal("health audits")
	}
}

func TestSecondGatewayInstanceFollowsTheChannel(t *testing.T) {
	h := newHarness(t)
	b, err := New(Options{KV: h.kv, Allow: h.ms, Marks: h.ms, TTL: 30 * time.Second, Renew: 10 * time.Second, Now: h.clk.now, Origin: "gw-b"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	go func() { _ = b.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	lease, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i1", []string{"/api/orders"}))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := b.Table().Match("GET", "/api/orders/ping"); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := b.Table().Match("GET", "/api/orders/ping"); !ok || b.Version() != h.reg.Version() {
		t.Fatalf("second instance did not pick up the registration (v %d vs %d)", b.Version(), h.reg.Version())
	}
	// A lease issued by A can be renewed through B.
	if _, err := b.Renew(h.ctx, idOrders, lease.ID); err != nil {
		t.Fatal(err)
	}
	// Marks announced by A are refreshed by B.
	_ = h.ms.SetMark(h.ctx, store.Mark{ID: "m1", Module: "orders", Mark: "draining"})
	h.reg.ApplyMark(h.ctx, "orders", "draining")
	for time.Now().Before(deadline) {
		if b.State("orders") == StateDraining {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if b.State("orders") != StateDraining {
		t.Fatal("mark not propagated")
	}
	// Withdrawal propagates too; a fresh instance loads everything from the KV.
	_ = h.ms.ClearMark(h.ctx, "orders")
	h.reg.ApplyMark(h.ctx, "orders", "")
	c, _ := New(Options{KV: h.kv, Allow: h.ms, Marks: h.ms, Now: h.clk.now})
	if err := c.Load(h.ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Table().Match("GET", "/api/orders/ping"); !ok || c.Version() == 0 {
		t.Fatal("cold load")
	}
	if err := h.reg.Deregister(h.ctx, idOrders, lease.ID); err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(deadline) {
		if _, ok := b.Table().Match("GET", "/api/orders/ping"); !ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := b.Table().Match("GET", "/api/orders/ping"); ok {
		t.Fatal("withdrawal not propagated")
	}
	// Own messages and garbage are ignored.
	b.onMessage(ctx, `{"kind":"registered","module":"x","origin":"gw-b"}`)
	b.onMessage(ctx, `not json`)
	b.onMessage(ctx, `{"kind":"exploded","module":"x","origin":"gw-a"}`)
}

func TestKVFailuresAndOptions(t *testing.T) {
	h := newHarness(t)
	if _, err := New(Options{}); err == nil {
		t.Fatal("options")
	}
	lease, _ := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i1", []string{"/api/orders"}))
	h.kv.Fail = errors.New("valkey down")
	if _, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i2", []string{"/api/orders"})); code(err) != codes.Unavailable {
		t.Fatalf("register with kv down: %v", err)
	}
	if _, be := h.reg.Backends("orders"); len(be) != 1 {
		t.Fatalf("failed registration must be rolled back: %+v", be)
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, lease.ID); code(err) != codes.Unavailable {
		t.Fatalf("renew with kv down: %v", err)
	}
	if err := h.reg.Load(h.ctx); err == nil {
		t.Fatal("load with kv down")
	}
	// A failing allow-list store is unavailable, not a refusal.
	h.kv.Fail = nil
	h.ms.Fail = errors.New("db down")
	if _, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i2", []string{"/api/orders"})); code(err) != codes.Unavailable {
		t.Fatalf("register with db down: %v", err)
	}
	if err := h.reg.RefreshMarks(h.ctx); err == nil {
		t.Fatal("marks with db down")
	}
	if err := h.reg.Load(h.ctx); err == nil {
		t.Fatal("load with db down")
	}
	h.ms.Fail = nil
	// Corrupt KV entries are reported, not applied.
	_ = h.kv.Set(h.ctx, regKey("bad"), "{", 0)
	if err := h.reg.Load(h.ctx); err == nil {
		t.Fatal("corrupt entry accepted")
	}
	_ = h.kv.Del(h.ctx, regKey("bad"))
	// Sweep with a failing KV withdraws nothing.
	h.kv.Fail = errors.New("down")
	h.reg.Sweep(h.ctx)
	h.kv.Fail = nil
	if _, be := h.reg.Backends("orders"); len(be) != 1 {
		t.Fatal("sweep must not act on kv errors")
	}
	// Run without marks store and with a KV that cannot subscribe still sweeps.
	noMarks, _ := New(Options{KV: h.kv, Allow: h.ms, Sweep: 5 * time.Millisecond, Now: h.clk.now})
	ctx, cancel := context.WithTimeout(h.ctx, 60*time.Millisecond)
	defer cancel()
	if err := noMarks.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := noMarks.RefreshMarks(h.ctx); err != nil {
		t.Fatal(err)
	}
	// Helpers.
	if !newer("1.10.0", "1.9.9") || newer("1.0.0", "1.0.0") || newer("0.1", "0.1.1") || !granted([]string{"/api"}, "/api/x") || granted([]string{"/api"}, "/apix") {
		t.Fatal("helpers")
	}
	if len(newID()) != 32 || itoa(0) != "0" || itoa(120) != "120" {
		t.Fatal("ids")
	}
}

func TestMemoryKV(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	clk := &clock{t: time.Now()}
	m.Now = clk.now
	_ = m.Set(ctx, "a", "1", time.Second)
	_ = m.Set(ctx, "b", "2", 0)
	if n, _ := m.Incr(ctx, "c", time.Second); n != 1 {
		t.Fatal(n)
	}
	if n, _ := m.Incr(ctx, "c", 0); n != 2 {
		t.Fatal(n)
	}
	if keys, _ := m.Keys(ctx, ""); len(keys) != 3 {
		t.Fatal(keys)
	}
	clk.t = clk.t.Add(2 * time.Second)
	if _, ok, _ := m.Get(ctx, "a"); ok {
		t.Fatal("ttl")
	}
	if keys, _ := m.Keys(ctx, ""); len(keys) != 1 {
		t.Fatal(keys)
	}
	got := ""
	ctx2, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = m.Subscribe(ctx2, "ch", func(s string) { got = s }); close(done) }()
	time.Sleep(10 * time.Millisecond)
	_ = m.Publish(ctx, "ch", "hello")
	cancel()
	<-done
	if got != "hello" {
		t.Fatal(got)
	}
	m.Fail = errors.New("x")
	if _, _, err := m.Get(ctx, "b"); err == nil {
		t.Fatal("fail")
	}
	if _, err := m.Incr(ctx, "b", 0); err == nil {
		t.Fatal("fail")
	}
	if _, err := m.Keys(ctx, ""); err == nil {
		t.Fatal("fail")
	}
	if m.Publish(ctx, "ch", "x") == nil || m.Set(ctx, "k", "v", 0) == nil || m.Del(ctx, "k") == nil {
		t.Fatal("fail")
	}
	m.Close()
}

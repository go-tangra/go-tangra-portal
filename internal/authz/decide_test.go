package authz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
)

type fakeChecker struct {
	calls   int
	asked   []string
	err     error
	version string
	allow   map[string]bool
	short   bool
	// blankReason omits the reason so the decider applies its default.
	blankReason bool
}

func (f *fakeChecker) BatchCheck(_ context.Context, in *authv1.BatchCheckRequest, _ ...grpc.CallOption) (*authv1.BatchCheckResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	resp := &authv1.BatchCheckResponse{}
	for _, p := range in.Permissions {
		// Decisions are per module: the fake keys grants by module:res:act.
		ref := p.Module + ":" + p.Resource + ":" + p.Action
		f.asked = append(f.asked, ref)
		r := &authv1.CheckResponse{Allowed: f.allow[ref], PolicyVersion: f.version, Reason: "no_permission"}
		if r.Allowed {
			r.Reason = "role:admin"
		}
		if f.blankReason {
			r.Reason = ""
		}
		resp.Results = append(resp.Results, r)
	}
	if f.short && len(resp.Results) > 0 {
		resp.Results = resp.Results[:len(resp.Results)-1]
	}
	return resp, nil
}

func TestDecisionsAndCache(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	fc := &fakeChecker{version: "v1", allow: map[string]bool{"orders:orders:read": true}}
	kv := registry.NewMemory()
	d, err := New(Options{Client: fc, KV: kv, Audit: aw})
	if err != nil || d.o.TTL != 2*time.Second {
		t.Fatal(err)
	}
	ok, err := d.Allowed(ctx, "orders", "t1", "u1", "orders:read")
	if err != nil || !ok || fc.calls != 1 {
		t.Fatalf("%v %v", ok, err)
	}
	// Cached: no second call within the TTL.
	if ok, _ := d.Allowed(ctx, "orders", "t1", "u1", "orders:read"); !ok || fc.calls != 1 {
		t.Fatalf("cache miss calls=%d", fc.calls)
	}
	if ok, err := d.Allowed(ctx, "orders", "t1", "u1", "orders:write"); ok || err != nil || fc.calls != 2 {
		t.Fatalf("%v %v %d", ok, err, fc.calls)
	}
	// Batch: one cached, one new, one invalid.
	ds, err := d.Check(ctx, "t1", "u1", []Ref{{"orders", "orders:read"}, {"billing", "billing:read"}, {"orders", "bogus"}})
	if err != nil || !ds[0].Allowed || ds[1].Allowed || ds[2].Reason != "unknown_permission" || fc.calls != 3 || len(fc.asked) != 3 {
		t.Fatalf("%+v %v asked=%v", ds, err, fc.asked)
	}
	if d.TenantVersion("t1") != "v1" || d.TenantVersion("t9") != "" {
		t.Fatal("version")
	}
	// A new tenant version (observed on the next fresh answer) invalidates cached decisions.
	fc.version = "v2"
	fc.allow["orders:orders:write"] = true
	if ok, _ := d.Allowed(ctx, "orders", "t1", "u1", "orders:read"); !ok || fc.calls != 3 {
		t.Fatalf("still cached under v1: calls=%d", fc.calls)
	}
	ds, _ = d.Check(ctx, "t1", "u1", []Ref{{"billing", "billing:write"}})
	if ds[0].Allowed || d.TenantVersion("t1") != "v2" || fc.calls != 4 {
		t.Fatalf("%+v", ds)
	}
	if ok, _ := d.Allowed(ctx, "orders", "t1", "u1", "orders:write"); !ok || fc.calls != 5 {
		t.Fatalf("v1 denial reused after version change: calls=%d", fc.calls)
	}
	if ok, _ := d.Allowed(ctx, "orders", "t1", "u1", "orders:read"); !ok || fc.calls != 6 {
		t.Fatalf("v1 cache reused after version change: calls=%d", fc.calls)
	}
	// Outage: denied, ErrUnavailable, audited as failed.
	fc.err = errors.New("down")
	if ok, err := d.Allowed(ctx, "orders", "t1", "u1", "billing:read"); ok || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outage: %v %v", ok, err)
	}
	fc.err = nil
	fc.short = true
	if _, err := d.Check(ctx, "t1", "u1", []Ref{{"mod", "a:b"}, {"mod", "c:d"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("short response accepted")
	}
	fc.short = false
	// Empty version: no caching.
	fc.version = ""
	d2, _ := New(Options{Client: fc, KV: registry.NewMemory()})
	_, _ = d2.Allowed(ctx, "mod", "t2", "u", "x:y")
	_, _ = d2.Allowed(ctx, "mod", "t2", "u", "x:y")
	if d2.TenantVersion("t2") != "" {
		t.Fatal("version recorded")
	}
	// Cache expiry.
	fc.version = "v3"
	clk := time.Now()
	kv.Now = func() time.Time { return clk }
	d3, _ := New(Options{Client: fc, KV: kv, TTL: time.Second})
	before := fc.calls
	_, _ = d3.Allowed(ctx, "orders", "t3", "u", "orders:read")
	_, _ = d3.Allowed(ctx, "orders", "t3", "u", "orders:read")
	if fc.calls != before+1 {
		t.Fatal("not cached")
	}
	clk = clk.Add(2 * time.Second)
	_, _ = d3.Allowed(ctx, "orders", "t3", "u", "orders:read")
	if fc.calls != before+2 {
		t.Fatal("cache did not expire")
	}
	aw.Close()
	refused, failed := 0, 0
	for _, r := range ms.Audit() {
		if r.EventType == "permission_refused" {
			if r.Outcome == "failed" {
				failed++
			} else {
				refused++
			}
		}
	}
	if refused < 1 || failed != 1 {
		t.Fatalf("audits refused=%d failed=%d", refused, failed)
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("options")
	}
}

// 019: every decision names the module that owns the permission; the same
// bare resource:action of two modules are different permissions.
func TestModuleScopedDecisions(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	fc := &fakeChecker{version: "v1", allow: map[string]bool{"warden:stats:read": true}}
	kv := registry.NewMemory()
	d, _ := New(Options{Client: fc, KV: kv, Audit: aw})

	// The request carries the module and the short resource/action.
	if ok, err := d.Allowed(ctx, "warden", "t1", "u1", "stats:read"); !ok || err != nil {
		t.Fatalf("warden stats:read: %v %v", ok, err)
	}
	if len(fc.asked) != 1 || fc.asked[0] != "warden:stats:read" {
		t.Fatalf("asked %v", fc.asked)
	}
	// The cache key includes the module.
	if raw, ok, _ := kv.Get(ctx, "gwdec:t1:u1:warden:stats:read@v1"); !ok || raw != "1:role:admin" {
		t.Fatalf("cache entry %q %v", raw, ok)
	}
	if _, ok, _ := kv.Get(ctx, "gwdec:t1:u1:stats:read@v1"); ok {
		t.Fatal("unqualified cache entry written")
	}
	// Negative: warden's grant does not satisfy ticket's stats:read, neither
	// from auth nor from the cached warden answer.
	if ok, err := d.Allowed(ctx, "ticket", "t1", "u1", "stats:read"); ok || err != nil {
		t.Fatalf("ticket stats:read allowed through warden's grant: %v %v", ok, err)
	}
	if fc.calls != 2 || fc.asked[1] != "ticket:stats:read" {
		t.Fatalf("ticket answered from warden's cache: calls=%d asked=%v", fc.calls, fc.asked)
	}
	// Both answers are cached separately.
	if ok, _ := d.Allowed(ctx, "warden", "t1", "u1", "stats:read"); !ok {
		t.Fatal("warden cache")
	}
	if ok, _ := d.Allowed(ctx, "ticket", "t1", "u1", "stats:read"); ok {
		t.Fatal("ticket cache")
	}
	if fc.calls != 2 {
		t.Fatalf("cache misses: calls=%d", fc.calls)
	}
	// One batch may mix modules.
	ds, err := d.Check(ctx, "t1", "u1", []Ref{{"asset", "stats:read"}, {"ipam", "stats:read"}})
	if err != nil || ds[0].Allowed || ds[1].Allowed || fc.calls != 3 || fc.asked[2] != "asset:stats:read" || fc.asked[3] != "ipam:stats:read" {
		t.Fatalf("%+v %v asked=%v", ds, err, fc.asked)
	}
	// Only bare refs of a named module are decided: qualified refs, a missing
	// or malformed module never reach auth (an empty module would evaluate
	// the legacy, unscoped permission).
	before := fc.calls
	ds, err = d.Check(ctx, "t1", "u1", []Ref{{"ticket", "warden:stats:read"}, {"", "stats:read"}, {"a:b", "stats:read"}, {"Warden", "stats:read"}, {"warden", "Stats:read"}})
	if err != nil || fc.calls != before {
		t.Fatalf("invalid refs asked: %v calls=%d", err, fc.calls)
	}
	for i, dd := range ds {
		if dd.Allowed || dd.Reason != "unknown_permission" {
			t.Fatalf("%d: %+v", i, dd)
		}
	}
	// Refusals are audited as before: route module + bare permission.
	aw.Close()
	found := false
	for _, r := range ms.Audit() {
		if r.EventType == "permission_refused" && r.Module == "ticket" && r.Outcome == "refused" && strings.Contains(string(r.Details), `"permission":"stats:read"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("refusal audit missing: %+v", ms.Audit())
	}
	if (Ref{"warden", "stats:read"}).String() != "warden:stats:read" {
		t.Fatal("Ref.String")
	}
}

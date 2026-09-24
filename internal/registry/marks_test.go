package registry

import (
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

func TestOpsDrainUndrainRevoke(t *testing.T) {
	h := newHarness(t)
	ops := &Ops{Reg: h.reg, Marks: h.ms, Allow: h.ms, Audit: h.aw, Now: h.clk.now}
	by := Operator{UserID: "op1", TenantID: "platform"}
	if err := ops.Drain(h.ctx, "ghost", by); !errors.Is(err, ErrUnknownModule) {
		t.Fatalf("drain unknown: %v", err)
	}
	lease, _ := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i1", []string{"/api/orders"}))
	if err := ops.Drain(h.ctx, "orders", by); err != nil {
		t.Fatal(err)
	}
	// Draining: routes stay in the table with the draining state (in-flight complete, new refused by the dispatcher),
	// renewals are refused, the mark is durable.
	if r, ok := h.reg.Table().Match("GET", "/api/orders/ping"); !ok || r.State != "draining" {
		t.Fatalf("%+v", r)
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, lease.ID); reason(err) != ReasonModuleDraining {
		t.Fatalf("renew while draining: %v", err)
	}
	if marks, _ := h.ms.ActiveMarks(h.ctx); len(marks) != 1 || marks[0].Mark != "draining" || marks[0].SetBy != "op1" {
		t.Fatalf("%+v", marks)
	}
	if err := ops.Undrain(h.ctx, "orders", by); err != nil {
		t.Fatal(err)
	}
	if err := ops.Undrain(h.ctx, "orders", by); !errors.Is(err, ErrUnknownModule) {
		t.Fatal("undrain twice")
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, lease.ID); err != nil {
		t.Fatalf("renew after undrain: %v", err)
	}
	if err := ops.Revoke(h.ctx, "orders", "short", by); !errors.Is(err, ErrReason) {
		t.Fatal("short reason accepted")
	}
	if err := ops.Revoke(h.ctx, "ghost", "decommissioned by the platform team", by); !errors.Is(err, ErrUnknownModule) {
		t.Fatal("revoke unknown")
	}
	if err := ops.Revoke(h.ctx, "orders", "decommissioned by the platform team", by); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.reg.Table().Match("GET", "/api/orders/ping"); ok {
		t.Fatal("revoked module still routable")
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, lease.ID); reason(err) != ReasonModuleRevoked {
		t.Fatalf("renew while revoked: %v", err)
	}
	if err := ops.Undrain(h.ctx, "orders", by); !errors.Is(err, ErrUnknownModule) {
		t.Fatal("undrain must not clear a revocation")
	}
	// Store failures surface.
	h.ms.Fail = errors.New("db down")
	if err := ops.Drain(h.ctx, "orders", by); err == nil {
		t.Fatal("drain with db down")
	}
	if err := ops.Revoke(h.ctx, "orders", "decommissioned by the platform team", by); err == nil {
		t.Fatal("revoke with db down")
	}
	h.ms.Fail = nil
	if h.auditCount(t, audit.ModuleDrained, "") != 1 || h.auditCount(t, audit.ModuleRevoked, "") != 1 || h.auditCount(t, audit.ModuleRecovered, "undrained") != 1 {
		t.Fatal("ops audits")
	}
}

func TestOpsAllowList(t *testing.T) {
	h := newHarness(t)
	ops := &Ops{Reg: h.reg, Marks: h.ms, Allow: h.ms, Audit: h.aw, Now: h.clk.now}
	by := Operator{UserID: "op1"}
	for name, e := range map[string]store.AllowEntry{
		"no spiffe":    {SpiffeID: "http://x", Prefixes: []string{"/a"}, Names: []string{"a1"}},
		"no prefixes":  {SpiffeID: "spiffe://example.org/svc/x", Names: []string{"x1"}},
		"bad prefix":   {SpiffeID: "spiffe://example.org/svc/x", Prefixes: []string{"/a/../b"}, Names: []string{"x1"}},
		"bad name":     {SpiffeID: "spiffe://example.org/svc/x", Prefixes: []string{"/a"}, Names: []string{"X!"}},
		"no names":     {SpiffeID: "spiffe://example.org/svc/x", Prefixes: []string{"/a"}},
		"too many":     {SpiffeID: "spiffe://example.org/svc/x", Prefixes: make([]string, 40), Names: []string{"x1"}},
		"short name":   {SpiffeID: "spiffe://example.org/svc/x", Prefixes: []string{"/a"}, Names: []string{"x"}},
		"upper prefix": {SpiffeID: "spiffe://example.org/svc/x", Prefixes: []string{"/a b"}, Names: []string{"x1"}},
	} {
		if _, err := ops.AddAllow(h.ctx, e, by); !errors.Is(err, ErrAllowEntry) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e, err := ops.AddAllow(h.ctx, store.AllowEntry{SpiffeID: idGhost, Prefixes: []string{"/api/ghost/"}, Names: []string{"ghost"}}, by)
	if err != nil || e.ID == "" || e.Prefixes[0] != "/api/ghost" || e.CreatedBy != "op1" {
		t.Fatalf("%+v %v", e, err)
	}
	// The next registration of that identity is accepted; revoking the entry refuses the one after.
	if _, err := h.reg.Register(h.ctx, idGhost, req("ghost", "1.0.0", "g1", []string{"/api/ghost"})); err != nil {
		t.Fatal(err)
	}
	if list, _ := ops.ListAllow(h.ctx); len(list) != 3 {
		t.Fatalf("%d entries", len(list))
	}
	if err := ops.RevokeAllow(h.ctx, e.ID, by); err != nil {
		t.Fatal(err)
	}
	if err := ops.RevokeAllow(h.ctx, e.ID, by); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revoke twice")
	}
	if _, err := h.reg.Register(h.ctx, idGhost, req("ghost", "1.0.0", "g2", []string{"/api/ghost"})); reason(err) != ReasonIdentityNotAllowed {
		t.Fatalf("after allow revocation: %v", err)
	}
	if _, err := ops.AddAllow(h.ctx, store.AllowEntry{SpiffeID: idOrders, Prefixes: []string{"/x"}, Names: []string{"orders"}}, by); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate active identity: %v", err)
	}
	if h.auditCount(t, audit.AllowlistChanged, "added") != 1 || h.auditCount(t, audit.AllowlistChanged, "revoked") != 1 {
		t.Fatal("allow audits")
	}
	if (&Ops{}).now().IsZero() {
		t.Fatal("now")
	}
}

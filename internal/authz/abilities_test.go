package authz

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
)

func TestPackUnpack(t *testing.T) {
	cases := []manifest.Ability{
		{Action: []string{"read"}, Subject: []string{"Order"}, Requires: "orders:read"},
		{Action: []string{"update", "delete"}, Subject: []string{"Order", "Line"}, Conditions: map[string]any{"ownerId": "u1"}, Requires: "orders:write"},
		{Action: []string{"read"}, Subject: []string{"Invoice"}, Inverted: true, Reason: "not yet", Requires: "billing:read"},
		{Action: []string{"read"}, Subject: []string{"Invoice"}, Fields: []string{"total", "due"}, Requires: "billing:read"},
	}
	want := []int{2, 3, 6, 5}
	for i, a := range cases {
		p := Pack(a)
		if len(p) != want[i] {
			t.Fatalf("%d: %v", i, p)
		}
		raw, _ := json.Marshal(p)
		var back PackedRule
		_ = json.Unmarshal(raw, &back)
		u, err := Unpack(back)
		if err != nil || u.Action[0] != a.Action[0] || len(u.Subject) != len(a.Subject) || u.Inverted != a.Inverted || u.Reason != a.Reason || len(u.Fields) != len(a.Fields) || (a.Conditions != nil) != (u.Conditions != nil) || u.Requires != "" {
			t.Fatalf("%d: %+v → %v → %+v (%v)", i, a, p, u, err)
		}
	}
	if _, err := Unpack(PackedRule{"read"}); err == nil {
		t.Fatal("short")
	}
	if _, err := Unpack(PackedRule{1, 2}); err == nil {
		t.Fatal("types")
	}
	if u, _ := Unpack(PackedRule{"a", "B", 0, 1.0}); !u.Inverted {
		t.Fatal("float inverted")
	}
}

func TestAbilitiesFollowDecisions(t *testing.T) {
	ctx := context.Background()
	regs := []registry.Registration{
		{Module: "orders", Manifest: manifest.Manifest{Abilities: []manifest.Ability{
			{Action: []string{"read"}, Subject: []string{"Order"}, Requires: "orders:read"},
			{Action: []string{"delete"}, Subject: []string{"Order"}, Requires: "orders:admin"}}}},
		{Module: "billing", Manifest: manifest.Manifest{Abilities: []manifest.Ability{{Action: []string{"read"}, Subject: []string{"Invoice"}, Requires: "billing:read"}}}},
		{Module: "empty"},
	}
	fc := &fakeChecker{version: "v1", allow: map[string]bool{"orders:read": true}}
	d, _ := New(Options{Client: fc, KV: registry.NewMemory()})
	doc, err := d.Abilities(ctx, regs, "t1", "u1", []string{"member"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Modules) != 1 || len(doc.Modules["orders"]) != 1 || doc.Modules["orders"][0][1] != "Order" || doc.Version != "7.v1" || doc.Roles[0] != "member" || doc.Tenant != "t1" {
		t.Fatalf("%+v", doc)
	}
	if fc.calls != 1 || len(fc.asked) != 3 {
		t.Fatalf("one batch for all distinct permissions: calls=%d asked=%v", fc.calls, fc.asked)
	}
	raw, _ := json.Marshal(doc)
	if string(raw) == "" || !json.Valid(raw) {
		t.Fatal("json")
	}
	// Grant more: the version follows the tenant policy version.
	fc.allow["billing:read"] = true
	fc.version = "v2"
	d2, _ := New(Options{Client: fc, KV: registry.NewMemory()})
	doc, _ = d2.Abilities(ctx, regs, "t1", "u1", nil, 8)
	if len(doc.Modules) != 2 || doc.Version != "8.v2" || doc.Roles == nil {
		t.Fatalf("%+v", doc)
	}
	fc.err = errors.New("down")
	d3, _ := New(Options{Client: fc, KV: registry.NewMemory()})
	if _, err := d3.Abilities(ctx, regs, "t1", "u1", nil, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("outage must not yield abilities")
	}
	if held, err := d3.Held(ctx, "t1", "u1", nil); err != nil || len(held) != 0 {
		t.Fatal("empty held")
	}
}

func TestPackTrimmingAndUnpackEdges(t *testing.T) {
	// Conditions without inverted/fields/reason: trimmed to three entries.
	p := Pack(manifest.Ability{Action: []string{"read"}, Subject: []string{"Order"}, Conditions: map[string]any{"a": 1}})
	if len(p) != 3 || falsy(p[2]) {
		t.Fatalf("%v", p)
	}
	if !falsy(0) || !falsy("") || falsy(map[string]any{}) || falsy(1) {
		t.Fatal("falsy")
	}
	// Unpack tolerates missing or oddly typed optional entries.
	u, err := Unpack(PackedRule{"read", "Order", map[string]any{"a": 1}, 0, 0, ""})
	if err != nil || u.Conditions == nil || u.Inverted || u.Fields != nil {
		t.Fatalf("%+v %v", u, err)
	}
	u, _ = Unpack(PackedRule{"read", "Order", 0, 1, "f1,f2", "why"})
	if !u.Inverted || len(u.Fields) != 2 || u.Reason != "why" {
		t.Fatalf("%+v", u)
	}
	u, _ = Unpack(PackedRule{"read", "Order", "not-a-map", "x", 7, 9})
	if u.Conditions != nil || u.Inverted || u.Fields != nil || u.Reason != "" {
		t.Fatalf("%+v", u)
	}
}

func TestAllowedDefaultReason(t *testing.T) {
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	fc := &fakeChecker{version: "v1", allow: map[string]bool{}, blankReason: true}
	d, _ := New(Options{Client: fc, KV: registry.NewMemory(), Audit: aw})
	if ok, err := d.Allowed(context.Background(), "m", "t", "u", "x:y"); ok || err != nil {
		t.Fatal(ok, err)
	}
	aw.Close()
	for _, r := range ms.Audit() {
		if r.EventType == "permission_refused" && r.Reason == "no_permission" {
			return
		}
	}
	t.Fatal("default reason missing")
}

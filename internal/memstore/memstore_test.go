package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

func TestAllowAndMarks(t *testing.T) {
	ctx := context.Background()
	m := New()
	if err := m.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}}); err != nil {
		t.Fatal(err)
	}
	if err := m.InsertAllow(ctx, store.AllowEntry{ID: "b", SpiffeID: "spiffe://example.org/svc/orders"}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("duplicate")
	}
	e, err := m.AllowBySpiffeID(ctx, "spiffe://example.org/svc/orders")
	if err != nil || e.Prefixes[0] != "/api/orders" || e.CreatedAt.IsZero() {
		t.Fatalf("%+v %v", e, err)
	}
	if _, err := m.AllowBySpiffeID(ctx, "spiffe://example.org/svc/ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("ghost")
	}
	if err := m.RevokeAllow(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeAllow(ctx, "a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revoke twice")
	}
	if _, err := m.AllowBySpiffeID(ctx, "spiffe://example.org/svc/orders"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revoked still active")
	}
	if l, _ := m.ListAllow(ctx); len(l) != 1 || l[0].RevokedAt == nil {
		t.Fatalf("%+v", l)
	}
	_ = m.SetMark(ctx, store.Mark{ID: "m1", Module: "orders", Mark: "draining"})
	_ = m.SetMark(ctx, store.Mark{ID: "m2", Module: "orders", Mark: "revoked"})
	if ms, _ := m.ActiveMarks(ctx); len(ms) != 1 || ms[0].Mark != "revoked" || ms[0].SetAt.IsZero() {
		t.Fatalf("%+v", ms)
	}
	if err := m.ClearMark(ctx, "orders"); err != nil {
		t.Fatal(err)
	}
	if err := m.ClearMark(ctx, "orders"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("clear twice")
	}
	if ms, _ := m.ActiveMarks(ctx); len(ms) != 0 {
		t.Fatal(ms)
	}
}

func TestAuditAndFailure(t *testing.T) {
	ctx := context.Background()
	m := New()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		_ = m.InsertAuditRows(ctx, []store.AuditRow{{TS: base.Add(time.Duration(i) * time.Minute), EventType: "registration_accepted", Module: "orders"}})
	}
	_ = m.InsertAuditRows(ctx, []store.AuditRow{{TS: base, EventType: "module_drained", Module: "billing"}})
	rows, _ := m.QueryAudit(ctx, "orders", "", base, base.Add(time.Hour), time.Time{}, 3)
	if len(rows) != 3 || !rows[0].TS.After(rows[1].TS) {
		t.Fatalf("%+v", rows)
	}
	rows, _ = m.QueryAudit(ctx, "", "module_drained", base, base.Add(time.Hour), time.Time{}, 10)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	rows, _ = m.QueryAudit(ctx, "orders", "", base, base.Add(time.Hour), base.Add(2*time.Minute), 10)
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	if len(m.Audit()) != 6 {
		t.Fatal("copy")
	}
	m.Fail = errors.New("down")
	if _, err := m.AllowBySpiffeID(ctx, "x"); err == nil {
		t.Fatal("fail injection")
	}
	for _, err := range []error{m.InsertAllow(ctx, store.AllowEntry{}), m.RevokeAllow(ctx, "a"), m.SetMark(ctx, store.Mark{}), m.ClearMark(ctx, "x"), m.InsertAuditRows(ctx, nil)} {
		if err == nil {
			t.Fatal("fail injection")
		}
	}
	if _, err := m.ListAllow(ctx); err == nil {
		t.Fatal("fail injection")
	}
	if _, err := m.ActiveMarks(ctx); err == nil {
		t.Fatal("fail injection")
	}
	if _, err := m.QueryAudit(ctx, "", "", base, base, base, 1); err == nil {
		t.Fatal("fail injection")
	}
}

// Mirrors store.TestKnownModules (integration) so tests using memstore see
// the same known-module semantics as Postgres.
func TestKnownModules(t *testing.T) {
	ctx := context.Background()
	m := New()
	t0 := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return t0.Add(2 * time.Minute) }
	see := func(k store.KnownModule) {
		t.Helper()
		if err := m.SeeKnown(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	see(store.KnownModule{Module: "sms-gw", Identity: "id", DisplayName: "SMS Gateway", LastVersion: "4.1.1", ManifestHash: "h1", LastSeenAt: t0})
	see(store.KnownModule{Module: "sms-gw", Identity: "id", DisplayName: "SMS Gateway", LastVersion: "4.2.0", ManifestHash: "h2", LastSeenAt: t0.Add(time.Minute)})
	see(store.KnownModule{Module: "sms-gw", Identity: "id", DisplayName: "SMS Gateway", ManifestHash: "h2", LastSeenAt: t0.Add(-time.Hour)})
	got, _ := m.ListKnown(ctx)
	if len(got) != 1 || !got[0].FirstSeenAt.Equal(t0) || !got[0].LastSeenAt.Equal(t0.Add(time.Minute)) || got[0].LastVersion != "4.2.0" || !got[0].Expected {
		t.Fatalf("%+v", got)
	}
	if err := m.SetKnownExpected(ctx, "sms-gw", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.ListKnown(ctx); got[0].Expected {
		t.Fatal("expected not cleared")
	}
	if err := m.ForgetKnown(ctx, "sms-gw"); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.ListKnown(ctx); len(got) != 0 {
		t.Fatal("forgotten module still listed")
	}
	for name, err := range map[string]error{
		"expected on forgotten": m.SetKnownExpected(ctx, "sms-gw", true),
		"forget twice":          m.ForgetKnown(ctx, "sms-gw"),
		"expected on unknown":   m.SetKnownExpected(ctx, "nope", true),
		"forget unknown":        m.ForgetKnown(ctx, "nope"),
	} {
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	see(store.KnownModule{Module: "sms-gw", Identity: "id", DisplayName: "SMS Gateway", LastVersion: "4.2.0", LastSeenAt: t0.Add(3 * time.Minute)})
	if got, _ := m.ListKnown(ctx); len(got) != 1 || got[0].ForgottenAt != nil || !got[0].FirstSeenAt.Equal(t0) {
		t.Fatalf("%+v", got)
	}
}

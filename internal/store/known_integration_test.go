//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestKnownModules covers migration 0005 as gateway_app: first/last seen,
// last-seen never moving backwards, an empty version never blanking the
// known one, expected and forget, and re-registration un-forgetting.
func TestKnownModules(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tx := func(fn func(pgx.Tx) error) error { return st.Tx(ctx, fn) }
	list := func() []KnownModule {
		t.Helper()
		var out []KnownModule
		if err := tx(func(tx pgx.Tx) (err error) { out, err = ListKnown(ctx, tx); return }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	see := func(m KnownModule) {
		t.Helper()
		if err := tx(func(tx pgx.Tx) error { return SeeKnown(ctx, tx, m) }); err != nil {
			t.Fatal(err) // gateway_app needs INSERT/UPDATE on known_modules (0005)
		}
	}
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	see(KnownModule{Module: "sms-gw", Identity: "spiffe://x/svc/sms-gw", DisplayName: "SMS Gateway", LastVersion: "4.1.1", ManifestHash: "h1", LastSeenAt: t0})
	see(KnownModule{Module: "sms-gw", Identity: "spiffe://x/svc/sms-gw", DisplayName: "SMS Gateway", LastVersion: "4.2.0", ManifestHash: "h2", LastSeenAt: t0.Add(time.Minute)})
	// An older write (another replica) and a report without a version change nothing they should not.
	see(KnownModule{Module: "sms-gw", Identity: "spiffe://x/svc/sms-gw", DisplayName: "SMS Gateway", ManifestHash: "h2", LastSeenAt: t0.Add(-time.Hour)})
	got := list()
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	m := got[0]
	if !m.FirstSeenAt.Equal(t0) || !m.LastSeenAt.Equal(t0.Add(time.Minute)) || m.LastVersion != "4.2.0" || m.ManifestHash != "h2" || !m.Expected || m.ForgottenAt != nil {
		t.Fatalf("%+v", m)
	}

	if err := tx(func(tx pgx.Tx) error { return SetKnownExpected(ctx, tx, "sms-gw", false) }); err != nil {
		t.Fatal(err)
	}
	if list()[0].Expected {
		t.Fatal("expected not cleared")
	}
	if err := tx(func(tx pgx.Tx) error { return ForgetKnown(ctx, tx, "sms-gw", t0.Add(2*time.Minute)) }); err != nil {
		t.Fatal(err)
	}
	if len(list()) != 0 {
		t.Fatal("forgotten module still listed")
	}
	for name, fn := range map[string]func(pgx.Tx) error{
		"expected on forgotten": func(tx pgx.Tx) error { return SetKnownExpected(ctx, tx, "sms-gw", true) },
		"forget twice":          func(tx pgx.Tx) error { return ForgetKnown(ctx, tx, "sms-gw", t0) },
		"expected on unknown":   func(tx pgx.Tx) error { return SetKnownExpected(ctx, tx, "nope", true) },
		"forget unknown":        func(tx pgx.Tx) error { return ForgetKnown(ctx, tx, "nope", t0) },
	} {
		if err := tx(fn); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Registering again makes it known again; the expected mark survives.
	see(KnownModule{Module: "sms-gw", Identity: "spiffe://x/svc/sms-gw", DisplayName: "SMS Gateway", LastVersion: "4.2.0", ManifestHash: "h2", LastSeenAt: t0.Add(3 * time.Minute)})
	got = list()
	if len(got) != 1 || got[0].ForgottenAt != nil || !got[0].FirstSeenAt.Equal(t0) {
		t.Fatalf("%+v", got)
	}
}

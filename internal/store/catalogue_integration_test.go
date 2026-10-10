//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestCatalogueTables covers migration 0006 as gateway_app: owners seeded
// once and replaced, sources unique by repo and by module, entries ordered by
// version (4.10.0 after 4.9.0) and their bundles read back.
func TestCatalogueTables(t *testing.T) {
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
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(tx(func(tx pgx.Tx) error { return SeedAllowedOwners(ctx, tx, []string{"go-tangra"}) }))
	must(tx(func(tx pgx.Tx) error { return SeedAllowedOwners(ctx, tx, []string{"other"}) })) // not empty: no change
	var owners []string
	must(tx(func(tx pgx.Tx) (err error) { owners, err = ListAllowedOwners(ctx, tx); return }))
	if len(owners) != 1 || owners[0] != "go-tangra" {
		t.Fatal(owners)
	}
	must(tx(func(tx pgx.Tx) error { return ReplaceAllowedOwners(ctx, tx, []string{"acme", "go-tangra"}, "op") }))

	must(tx(func(tx pgx.Tx) error { return AddSource(ctx, tx, "go-tangra/go-tangra-sms-gw", "op") }))
	must(tx(func(tx pgx.Tx) error { return AddSource(ctx, tx, "go-tangra/fork", "op") }))
	if err := tx(func(tx pgx.Tx) error { return AddSource(ctx, tx, "go-tangra/go-tangra-sms-gw", "op") }); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate source: %v", err)
	}
	must(tx(func(tx pgx.Tx) error { return SourceChecked(ctx, tx, "go-tangra/go-tangra-sms-gw", "sms-gw", "", time.Now()) }))
	if err := tx(func(tx pgx.Tx) error { return SourceChecked(ctx, tx, "go-tangra/fork", "sms-gw", "", time.Now()) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("module taken by a second source: %v", err)
	}
	for _, v := range []struct {
		version string
		key     int64
	}{{"4.9.0", 4_000_009_000_000}, {"4.10.0", 4_000_010_000_000}} {
		must(tx(func(tx pgx.Tx) error {
			return InsertEntry(ctx, tx, CatalogueEntry{Module: "sms-gw", Version: v.version, Repo: "go-tangra/go-tangra-sms-gw", VersionKey: v.key,
				Entry: []byte(`{"version":"` + v.version + `"}`), EntrySHA256: "e", Bundle: []byte("zip-" + v.version), BundleSHA256: "b", AttestedBy: "who", VerifiedAt: time.Now()})
		}))
	}
	var latest []CatalogueEntry
	must(tx(func(tx pgx.Tx) (err error) { latest, err = LatestEntries(ctx, tx); return }))
	if len(latest) != 1 || latest[0].Version != "4.10.0" || latest[0].Bundle != nil {
		t.Fatalf("%+v", latest)
	}
	var b []byte
	must(tx(func(tx pgx.Tx) (err error) { b, err = EntryBundle(ctx, tx, "sms-gw", "4.9.0"); return }))
	if string(b) != "zip-4.9.0" {
		t.Fatal(string(b))
	}
	must(tx(func(tx pgx.Tx) error { return RemoveSource(ctx, tx, "GO-TANGRA/fork") }))
	if err := tx(func(tx pgx.Tx) error { return RemoveSource(ctx, tx, "go-tangra/fork") }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
}

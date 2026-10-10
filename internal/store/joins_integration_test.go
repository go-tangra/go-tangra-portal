//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestCatalogueJoins covers migrations 0007 and 0008 as gateway_app: a
// download join keeps its jti; an agent join has none until rendered, keeps
// its host inputs, is rendered at most MaxJoinRenders times and never after
// it expires; download joins are never rendered.
func TestCatalogueJoins(t *testing.T) {
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
	now := time.Now().UTC().Truncate(time.Microsecond)
	const (
		download = "0190f7c2-6a3e-7c1a-9b2e-000000000d01"
		agent    = "0190f7c2-6a3e-7c1a-9b2e-000000000a01"
		expired  = "0190f7c2-6a3e-7c1a-9b2e-000000000a02"
		jti      = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
		host     = "0190f7c2-6a3e-7c1a-9b2e-000000000001"
		tenant   = "0190f7c2-6a3e-7c1a-9b2e-0000000000aa"
	)
	for _, j := range []CatalogueJoin{
		{ID: download, Module: "sms-gw", Version: "4.3.0", JTI: jti, MintedBy: "op", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		{ID: agent, Module: "sms-gw", Version: "4.3.0", MintedBy: "op", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Channel: JoinAgent, TenantID: tenant,
			HostID: host, Inputs: map[string]string{"MODULE_ADVERTISE_HOST": "pbx1"}},
		{ID: expired, Module: "sms-gw", Version: "4.3.0", MintedBy: "op", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), Channel: JoinAgent,
			TenantID: tenant, HostID: host},
	} {
		if err := tx(func(tx pgx.Tx) error { return InsertJoin(ctx, tx, j) }); err != nil {
			t.Fatal(err)
		}
	}
	var got CatalogueJoin
	if err := tx(func(tx pgx.Tx) (err error) { got, err = GetJoin(ctx, tx, download, now); return }); err != nil || got.Channel != JoinDownload || got.JTI != jti {
		t.Fatalf("%+v %v", got, err)
	}
	if err := tx(func(tx pgx.Tx) (err error) { got, err = GetJoin(ctx, tx, agent, now); return }); err != nil || got.Channel != JoinAgent || got.JTI != "" ||
		got.HostID != host || got.TenantID != tenant || got.Inputs["MODULE_ADVERTISE_HOST"] != "pbx1" || got.Renders != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	for _, id := range []string{download, expired} {
		if err := tx(func(tx pgx.Tx) error { _, err := ClaimJoinRender(ctx, tx, id, now); return err }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s rendered: %v", id, err)
		}
	}
	for i := 1; i <= MaxJoinRenders; i++ {
		if err := tx(func(tx pgx.Tx) (err error) { got, err = ClaimJoinRender(ctx, tx, agent, now); return }); err != nil || got.Renders != i {
			t.Fatalf("render %d: %+v %v", i, got, err)
		}
	}
	if err := tx(func(tx pgx.Tx) error { _, err := ClaimJoinRender(ctx, tx, agent, now); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("render past the budget: %v", err)
	}
	if err := tx(func(tx pgx.Tx) error { return SetJoinJTI(ctx, tx, agent, jti) }); err != nil {
		t.Fatal(err)
	}
	if err := tx(func(tx pgx.Tx) (err error) { got, err = GetJoin(ctx, tx, agent, now); return }); err != nil || got.JTI != jti {
		t.Fatalf("%+v %v", got, err)
	}
}

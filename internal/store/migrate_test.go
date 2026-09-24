//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startDB(t *testing.T) (adminDSN, appDSN string) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
			Env:        map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "gateway"},
			WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(2 * time.Minute),
		}, Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "5432/tcp")
	adminDSN = "postgres://postgres:test@" + host + ":" + port.Port() + "/gateway?sslmode=disable"
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Exec(ctx, "CREATE ROLE gateway_app LOGIN PASSWORD 'app'")
	_ = conn.Close(ctx)
	appDSN = "postgres://gateway_app:app@" + host + ":" + port.Port() + "/gateway?sslmode=disable"
	return
}

func TestMigrateAndRepos(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, adminDSN); err != nil { // idempotent
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := st.Tx(ctx, func(tx pgx.Tx) error {
		if err := InsertAllow(ctx, tx, AllowEntry{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}, CreatedBy: "ops", CreatedAt: now}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, func(tx pgx.Tx) error {
		return InsertAllow(ctx, tx, AllowEntry{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c56", SpiffeID: "spiffe://example.org/svc/orders", CreatedAt: now})
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate active spiffe id accepted: %v", err)
	}
	if err := st.Tx(ctx, func(tx pgx.Tx) error {
		e, err := AllowBySpiffeID(ctx, tx, "spiffe://example.org/svc/orders")
		if err != nil || e.Prefixes[0] != "/api/orders" || e.Names[0] != "orders" {
			t.Fatalf("%+v %v", e, err)
		}
		if err := RevokeAllow(ctx, tx, e.ID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := AllowBySpiffeID(ctx, tx, "spiffe://example.org/svc/orders"); !errors.Is(err, ErrNotFound) {
			t.Fatal("revoked entry still active")
		}
		if l, err := ListAllow(ctx, tx); err != nil || len(l) != 1 || l[0].RevokedAt == nil {
			t.Fatalf("%+v %v", l, err)
		}
		if err := SetMark(ctx, tx, Mark{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c57", Module: "orders", Mark: "draining", SetBy: "ops", SetAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := SetMark(ctx, tx, Mark{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c58", Module: "orders", Mark: "revoked", SetBy: "ops", SetAt: now}); err != nil {
			t.Fatal(err)
		}
		if m, err := ActiveMarks(ctx, tx); err != nil || len(m) != 1 || m[0].Mark != "revoked" {
			t.Fatalf("%+v %v", m, err)
		}
		if err := ClearMark(ctx, tx, "orders", now); err != nil {
			t.Fatal(err)
		}
		if err := ClearMark(ctx, tx, "orders", now); !errors.Is(err, ErrNotFound) {
			t.Fatal("clear twice")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertAuditRows(ctx, []AuditRow{{TS: now, EventType: "registration_accepted", Module: "orders", ActorKind: "service", Outcome: "ok", Details: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	_ = st.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := QueryAudit(ctx, tx, "orders", "", now.Add(-time.Hour), now.Add(time.Hour), time.Time{}, 10)
		if err != nil || len(rows) != 1 || rows[0].EventType != "registration_accepted" {
			t.Fatalf("%+v %v", rows, err)
		}
		// gateway_app must not be able to alter audit history.
		if _, err := tx.Exec(ctx, "UPDATE gateway_audit_events SET reason = 'x'"); err == nil {
			t.Fatal("audit rows are mutable by the app role")
		}
		return errors.New("rollback")
	})
	admin, _ := pgx.Connect(ctx, adminDSN)
	defer admin.Close(ctx)
	var n int
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM timescaledb_information.jobs WHERE proc_name = 'policy_retention'").Scan(&n)
	if n < 1 {
		t.Fatalf("retention jobs %d", n)
	}
}

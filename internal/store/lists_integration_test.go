//go:build integration

package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// TestPageAudit covers the list contract on the hypertable: the id column
// added by migration 0004, counts within filters, clamping, and every event
// exactly once across pages for each sort field and direction even when
// events share a timestamp.
func TestPageAudit(t *testing.T) {
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
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	var rows []AuditRow
	for i := 0; i < 123; i++ {
		rows = append(rows, AuditRow{TS: base.Add(time.Duration(i/3) * time.Second), EventType: []string{"module_drained", "allowlist_changed"}[i%2],
			Module: []string{"Alpha", "beta", "gamma"}[i%3], ActorKind: "operator", Outcome: "ok", SubjectID: fmt.Sprint(i), Details: []byte(`{}`)})
	}
	if err := st.Tx(ctx, func(tx pgx.Tx) error { return InsertAuditRows(ctx, tx, rows) }); err != nil {
		t.Fatal(err) // gateway_app needs USAGE on the id sequence (0004)
	}
	window := AuditQuery{From: base.Add(-time.Minute), To: time.Now().UTC()}
	page := func(q AuditQuery, req listquery.Request) ([]AuditRow, int, listquery.Request) {
		t.Helper()
		var out []AuditRow
		var total int
		var applied listquery.Request
		if err := st.Tx(ctx, func(tx pgx.Tx) (err error) { out, total, applied, err = PageAudit(ctx, tx, q, req); return }); err != nil {
			t.Fatal(err)
		}
		return out, total, applied
	}

	for _, sort := range []string{"ts", "module", "event_type"} {
		for _, dir := range []listquery.Dir{listquery.Asc, listquery.Desc} {
			seen := map[string]int{}
			for p := 1; p <= 20; p++ {
				items, total, applied := page(window, listquery.Request{Page: p, PageSize: 10, Sort: sort, Order: dir})
				if total != 123 {
					t.Fatalf("total %d", total)
				}
				if applied.Page != p {
					break
				}
				for _, it := range items {
					if it.ID == 0 {
						t.Fatal("id not populated")
					}
					seen[it.SubjectID]++
				}
			}
			if len(seen) != 123 {
				t.Fatalf("%s %s: %d distinct", sort, dir, len(seen))
			}
			for id, n := range seen {
				if n != 1 {
					t.Fatalf("%s %s: %s seen %d times", sort, dir, id, n)
				}
			}
		}
	}
	// Case-insensitive text sort: "Alpha" sorts before "beta".
	items, _, _ := page(window, listquery.Request{Page: 1, PageSize: 1, Sort: "module", Order: listquery.Asc})
	if items[0].Module != "Alpha" {
		t.Fatalf("text sort: %s", items[0].Module)
	}
	// Filters apply before counting; beyond the last page clamps.
	items, total, applied := page(AuditQuery{Module: "beta", From: window.From, To: window.To}, listquery.Request{Page: 9, PageSize: 25, Sort: "ts", Order: listquery.Desc})
	if total != 41 || applied.Page != 2 || len(items) != 16 {
		t.Fatalf("filtered clamp: total %d page %d len %d", total, applied.Page, len(items))
	}
	// An empty window → page 1, no rows.
	items, total, applied = page(AuditQuery{From: base.Add(-48 * time.Hour), To: base.Add(-47 * time.Hour)}, listquery.Request{Page: 3, PageSize: 25, Sort: "ts", Order: listquery.Desc})
	if total != 0 || applied.Page != 1 || len(items) != 0 {
		t.Fatalf("empty: %d %d %d", total, applied.Page, len(items))
	}

	// Both directions of the ts sort are served by gateway_audit_ts_id
	// (ts DESC, id DESC) without a Sort node: ts is NotNull, so OrderBy emits
	// no NULLS LAST and the index matches forward (desc) and backward (asc).
	for _, dir := range []listquery.Dir{listquery.Desc, listquery.Asc} {
		req := listquery.Request{Page: 1, PageSize: 25, Sort: "ts", Order: dir}
		plan := explainNoSort(t, st, `SELECT id, ts FROM gateway_audit_events WHERE ($1 = '' OR module = $1) AND ($2 = '' OR event_type = $2) AND ts >= $3 AND ts <= $4 ORDER BY `+
			req.OrderBy(AuditList)+` LIMIT 25`, "", "", window.From, window.To)
		if !strings.Contains(plan, "ts_id") {
			t.Fatalf("ts %s: audit index not used:\n%s", dir, plan)
		}
	}
}

var sortNode = regexp.MustCompile(`(?m)^\s*(->\s+)?(Incremental )?Sort\s*$`)

// explainNoSort returns the plan of query with sequential and bitmap scans
// disabled and fails if the planner still needs a Sort node, i.e. no index
// delivers the requested order.
func explainNoSort(t *testing.T, st *Store, query string, args ...any) string {
	t.Helper()
	var plan []string
	err := st.Tx(context.Background(), func(tx pgx.Tx) error {
		for _, set := range []string{"SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off"} {
			if _, err := tx.Exec(context.Background(), set); err != nil {
				return err
			}
		}
		rows, err := tx.Query(context.Background(), "EXPLAIN (COSTS OFF) "+query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan = append(plan, line)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Join(plan, "\n")
	if sortNode.MatchString(out) {
		t.Fatalf("plan sorts instead of scanning an index:\n%s", out)
	}
	return out
}

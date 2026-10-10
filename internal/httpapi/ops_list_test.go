package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

type pageBody[T any] struct {
	Items    []T    `json:"items"`
	Total    int    `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Sort     string `json:"sort"`
	Order    string `json:"order"`
}

func decodePage[T any](t *testing.T, body string) pageBody[T] {
	t.Helper()
	var p pageBody[T]
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return p
}

// seedAudit inserts n events: modules alternate a/b/c, one second apart,
// with every third pair sharing a timestamp (tie-breaker coverage).
func seedAudit(t *testing.T, ms interface {
	InsertAuditRows(context.Context, []store.AuditRow) error
}, n int, base time.Time) {
	t.Helper()
	rows := make([]store.AuditRow, 0, n)
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i/2) * time.Second)
		rows = append(rows, store.AuditRow{TS: ts, EventType: "module_drained", Module: []string{"a", "b", "c"}[i%3], ActorKind: "operator", Outcome: "ok", SubjectID: fmt.Sprint(i)})
	}
	if err := ms.InsertAuditRows(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
}

func TestOpsAuditPages(t *testing.T) {
	s, _, ms, _ := opsServer(t)
	op := map[string]string{"Authorization": "Bearer operator"}
	seedAudit(t, ms, 123, time.Now().Add(-time.Hour))
	// opsServer's registration is audited asynchronously and may land at any
	// point under load: the page counts cover only the seeded events.
	const seeded = "&event_type=module_drained"

	w := do(s, "GET", "/gateway/v1/ops/audit?page_size=50&module=a", "", op)
	p := decodePage[AuditView](t, w.Body.String())
	if w.Code != 200 || p.Total != 41 || p.Page != 1 || p.PageSize != 50 || len(p.Items) != 41 || p.Sort != "ts" || p.Order != "desc" {
		t.Fatalf("filtered page → %d %+v", w.Code, p)
	}
	// Every event exactly once across pages, for every sort and direction.
	for _, sort := range []string{"ts", "module", "event_type"} {
		for _, order := range []string{"asc", "desc"} {
			seen := map[string]int{}
			for page := 1; ; page++ {
				w := do(s, "GET", fmt.Sprintf("/gateway/v1/ops/audit?page=%d&page_size=10&sort=%s&order=%s"+seeded, page, sort, order), "", op)
				p := decodePage[AuditView](t, w.Body.String())
				if p.Page != page {
					break
				}
				for _, it := range p.Items {
					seen[it.SubjectID]++
				}
			}
			if len(seen) != 123 {
				t.Fatalf("%s %s: saw %d distinct events", sort, order, len(seen))
			}
			for id, n := range seen {
				if n != 1 {
					t.Fatalf("%s %s: event %s seen %d times", sort, order, id, n)
				}
			}
		}
	}
	// Newest first by default; beyond the last page → last page.
	w = do(s, "GET", "/gateway/v1/ops/audit?page=99&page_size=50"+seeded, "", op)
	p = decodePage[AuditView](t, w.Body.String())
	if p.Page != 3 || len(p.Items) != 23 || p.Total != 123 {
		t.Fatalf("clamp → %+v", p)
	}
	first := decodePage[AuditView](t, do(s, "GET", "/gateway/v1/ops/audit?page_size=1"+seeded, "", op).Body.String())
	if first.Items[0].SubjectID != "122" {
		t.Fatalf("default order: first is %s", first.Items[0].SubjectID)
	}
	// Outside the default 7-day window, an explicit from reaches older events.
	seedAudit(t, ms, 2, time.Now().Add(-30*24*time.Hour))
	if p := decodePage[AuditView](t, do(s, "GET", "/gateway/v1/ops/audit?"+seeded[1:], "", op).Body.String()); p.Total != 123 {
		t.Fatalf("default window total %d", p.Total)
	}
	from := time.Now().Add(-60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if p := decodePage[AuditView](t, do(s, "GET", "/gateway/v1/ops/audit?from="+from+seeded, "", op).Body.String()); p.Total != 125 {
		t.Fatalf("explicit window total %d", p.Total)
	}
}

func TestOpsListValidation(t *testing.T) {
	s, _, _, _ := opsServer(t)
	op := map[string]string{"Authorization": "Bearer operator"}
	for _, tc := range []struct{ path, param string }{
		{"/gateway/v1/ops/audit?page=0", "page"},
		{"/gateway/v1/ops/audit?page_size=201", "page_size"},
		{"/gateway/v1/ops/audit?page_size=abc", "page_size"},
		{"/gateway/v1/ops/audit?sort=actor_id", "sort"},
		{"/gateway/v1/ops/audit?sort=ts%3Bdrop%20table%20x", "sort"},
		{"/gateway/v1/ops/audit?order=up", "order"},
		{"/gateway/v1/ops/audit?cursor=2026-01-01T00:00:00Z&page=2", "cursor"},
		{"/gateway/v1/ops/allowlist?sort=prefixes", "sort"},
		{"/gateway/v1/ops/registrations?page_size=0", "page_size"},
		{"/gateway/v1/ops/registrations?sort=identity", "sort"},
	} {
		w := do(s, "GET", tc.path, "", op)
		if w.Code != 400 {
			t.Fatalf("%s → %d %s", tc.path, w.Code, w.Body.String())
		}
		body := w.Body.String()
		// The OpenAPI validator may answer first (no detail); listquery always names the parameter.
		if strings.Contains(body, `"detail"`) && !strings.Contains(body, `"param":"`+tc.param+`"`) {
			t.Fatalf("%s → %s (want param %s)", tc.path, body, tc.param)
		}
		if strings.Contains(body, "drop table") {
			t.Fatalf("%s echoed input: %s", tc.path, body)
		}
	}
}

// TestOpsAuditSpanCap: a from/to range wider than 90 days is refused with
// validation_failed naming "from" (never the value) on the paged and legacy
// paths; exactly 90 days is accepted (security review F-2).
func TestOpsAuditSpanCap(t *testing.T) {
	s, _, ms, _ := opsServer(t)
	op := map[string]string{"Authorization": "Bearer operator"}
	seedAudit(t, ms, 3, time.Now().Add(-time.Hour))
	to := time.Now().UTC().Truncate(time.Second)
	ts := func(t time.Time) string { return t.Format(time.RFC3339) }
	wide := "from=" + ts(to.Add(-91*24*time.Hour)) + "&to=" + ts(to)
	exact := "from=" + ts(to.Add(-90*24*time.Hour)) + "&to=" + ts(to)
	for _, path := range []string{
		"/gateway/v1/ops/audit?" + wide,
		"/gateway/v1/ops/audit?page_size=10&" + wide,
		"/gateway/v1/ops/audit?from=1970-01-01T00:00:00Z",
		"/gateway/v1/ops/audit?cursor=" + ts(to) + "&" + wide,
		"/gateway/v1/ops/audit?limit=10&from=1970-01-01T00:00:00Z",
	} {
		w := do(s, "GET", path, "", op)
		body := w.Body.String()
		if w.Code != 400 || !strings.Contains(body, `"reason":"validation_failed"`) || !strings.Contains(body, `"param":"from"`) {
			t.Fatalf("%s → %d %s", path, w.Code, body)
		}
		if strings.Contains(body, "1970") || strings.Contains(body, ts(to)) {
			t.Fatalf("%s echoed input: %s", path, body)
		}
	}
	if p := decodePage[AuditView](t, do(s, "GET", "/gateway/v1/ops/audit?"+exact, "", op).Body.String()); p.Total != 3 {
		t.Fatalf("90d page → %+v", p)
	}
	if w := do(s, "GET", "/gateway/v1/ops/audit?cursor="+ts(to.Add(time.Minute))+"&"+exact, "", op); w.Code != 200 || strings.Count(w.Body.String(), "module_drained") != 3 {
		t.Fatalf("90d legacy → %d %s", w.Code, w.Body.String())
	}
}

func TestOpsAuditLegacyCursor(t *testing.T) {
	s, _, ms, _ := opsServer(t)
	op := map[string]string{"Authorization": "Bearer operator"}
	seedAudit(t, ms, 3, time.Now().Add(-time.Hour))
	w := do(s, "GET", "/gateway/v1/ops/audit?cursor="+time.Now().UTC().Format(time.RFC3339Nano), "", op)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"events":[`) {
		t.Fatalf("legacy → %d %s", w.Code, w.Body.String())
	}
}

func TestOpsAllowlistAndRegistrationsPages(t *testing.T) {
	s, _, ms, _ := opsServer(t)
	op := map[string]string{"Authorization": "Bearer operator"}
	ctx := context.Background()
	revoked := time.Now().Add(-time.Minute)
	for i := 0; i < 30; i++ {
		e := store.AllowEntry{ID: fmt.Sprintf("id-%02d", i), SpiffeID: fmt.Sprintf("spiffe://example.org/svc/m%02d", i), Prefixes: []string{fmt.Sprintf("/api/m%02d", i)}, Names: []string{fmt.Sprintf("m%02d", i)}, CreatedAt: time.Now().Add(time.Duration(i) * time.Second)}
		if i%5 == 0 {
			e.RevokedAt = &revoked
		}
		if err := ms.InsertAllow(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	w := do(s, "GET", "/gateway/v1/ops/allowlist?page=2&page_size=10", "", op)
	p := decodePage[AllowView](t, w.Body.String())
	if w.Code != 200 || p.Total != 31 || len(p.Items) != 10 || p.Items[0].SpiffeID != "spiffe://example.org/svc/m10" {
		t.Fatalf("allow page 2 → %d %+v", w.Code, p)
	}
	p = decodePage[AllowView](t, do(s, "GET", "/gateway/v1/ops/allowlist?sort=revoked_at&order=desc&page_size=200", "", op).Body.String())
	if p.Items[0].RevokedAt == "" || p.Items[len(p.Items)-1].RevokedAt != "" {
		t.Fatalf("revoked_at desc: revoked first, active (null) last: %+v", p.Items)
	}
	p = decodePage[AllowView](t, do(s, "GET", "/gateway/v1/ops/allowlist?sort=created_at", "", op).Body.String())
	if p.Sort != "created_at" || p.Order != "desc" {
		t.Fatalf("created_at default direction: %s %s", p.Sort, p.Order)
	}
	r := decodePage[RegistrationView](t, do(s, "GET", "/gateway/v1/ops/registrations?sort=instances", "", op).Body.String())
	if r.Total != 1 || r.Items[0].Module != "orders" || r.Order != "desc" {
		t.Fatalf("registrations → %+v", r)
	}
	for _, sort := range []string{"module", "state", "last_renewal"} {
		if r := decodePage[RegistrationView](t, do(s, "GET", "/gateway/v1/ops/registrations?sort="+sort, "", op).Body.String()); r.Total != 1 {
			t.Fatalf("sort %s → %+v", sort, r)
		}
	}
}

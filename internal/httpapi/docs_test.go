package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/authz"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/listquery"
)

type docsIdentity struct{}

func (docsIdentity) Resolve(_ context.Context, r *http.Request) (identity.Identity, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer ok":
		return identity.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"member"}}, nil
	case "Bearer op":
		return identity.Identity{UserID: "u2", TenantID: "platform", Roles: []string{"platform-operator"}, Operator: true}, nil
	case "Bearer tenant-op": // operator role outside the platform tenant
		return identity.Identity{UserID: "u3", TenantID: "t1", Roles: []string{"platform-operator"}}, nil
	}
	return identity.Identity{}, identity.ErrAnonymous
}

// countingDecide counts Held batches.
type countingDecide struct {
	*fakeDecide
	mu    sync.Mutex
	calls int
	refs  []authz.Ref
}

func (c *countingDecide) Held(ctx context.Context, tenant, user string, refs []authz.Ref) (map[authz.Ref]bool, error) {
	c.mu.Lock()
	c.calls++
	c.refs = refs
	c.mu.Unlock()
	return c.fakeDecide.Held(ctx, tenant, user, refs)
}

// fakeDocs applies a scope the way the SQL does.
type fakeDocs struct {
	pages  []store.DocPage
	assets map[string]store.DocAsset
	scopes []store.DocsScope
	err    error
}

func (f *fakeDocs) inScope(s store.DocsScope, p store.DocPage) bool {
	return slices.Contains(s.Modules, p.Module) && (p.Requires == "" || slices.Contains(s.Held, p.Module+":"+p.Requires)) && (p.Audience != "operator" || s.Operator)
}

func (f *fakeDocs) DocsRequires(_ context.Context, modules []string) (map[string][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string][]string{}
	for _, p := range f.pages {
		if p.Requires != "" && slices.Contains(modules, p.Module) && !slices.Contains(out[p.Module], p.Requires) {
			out[p.Module] = append(out[p.Module], p.Requires)
		}
	}
	return out, nil
}

func (f *fakeDocs) SearchDocs(_ context.Context, q store.DocsSearch, req listquery.Request) (store.DocsResult, error) {
	f.scopes = append(f.scopes, q.Scope)
	res := store.DocsResult{Module: map[string]int{}, Kinds: map[string]int{}, Req: req}
	for _, p := range f.pages {
		if !f.inScope(q.Scope, p) || !strings.Contains(strings.ToLower(p.Title+" "+p.Body), strings.ToLower(q.Query)) {
			continue
		}
		res.Module[p.Module]++
		res.Kinds[p.Kind]++
		if (q.Module == "" || q.Module == p.Module) && (q.Kind == "" || q.Kind == p.Kind) {
			res.Total++
			res.Hits = append(res.Hits, store.DocHit{Module: p.Module, Slug: p.Slug, Title: p.Title, Kind: p.Kind, Summary: p.Summary,
				Snippet: strings.Replace(p.Body, q.Query, store.SnippetStart+q.Query+store.SnippetStop, 1), Rank: 0.5})
		}
	}
	return res, nil
}

func (f *fakeDocs) DocsTree(_ context.Context, s store.DocsScope) ([]store.DocEntry, error) {
	f.scopes = append(f.scopes, s)
	var out []store.DocEntry
	for _, p := range f.pages {
		if f.inScope(s, p) {
			out = append(out, store.DocEntry{Module: p.Module, Slug: p.Slug, Title: p.Title, Summary: p.Summary, Kind: p.Kind, Order: p.Order})
		}
	}
	return out, nil
}

func (f *fakeDocs) GetDoc(_ context.Context, s store.DocsScope, module, slug string) (store.DocPage, error) {
	for _, p := range f.pages {
		if p.Module == module && p.Slug == slug && f.inScope(s, p) {
			return p, nil
		}
	}
	return store.DocPage{}, store.ErrNotFound
}

func (f *fakeDocs) GetDocAsset(_ context.Context, module, path string) (store.DocAsset, error) {
	if a, ok := f.assets[module+"/"+path]; ok {
		return a, nil
	}
	return store.DocAsset{}, store.ErrNotFound
}

const pngSum = "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"

// docsServer: orders and billing are registered (shellServer); the member
// holds orders:orders:read only. Pages are in tree order (as the store
// returns them).
func docsServer(t *testing.T) (*Server, *fakeDocs, *countingDecide, func(module, mark string)) {
	t.Helper()
	s, reg, dec, _ := shellServer(t)
	cd := &countingDecide{fakeDecide: dec}
	fd := &fakeDocs{pages: []store.DocPage{
		{Module: "orders", Slug: "index", Kind: "guide", Title: "Orders", Summary: "Start here", Body: "Track every order <b>here</b>.", HTML: "<p>x</p>", Audience: "user"},
		{Module: "orders", Slug: "guides/refunds", Kind: "guide", Order: 2, Title: "Refunds", Body: "Refund an order.", Requires: "orders:read", Audience: "user",
			Outline: []store.DocHeading{{ID: "steps", Text: "Steps", Level: 2}}, Tags: []string{"money"}},
		{Module: "orders", Slug: "admin", Kind: "reference", Title: "Order admin", Body: "Admin of an order.", Requires: "orders:admin", Audience: "user"},
		{Module: "orders", Slug: "install", Kind: "reference", Title: "Install orders", Body: "Install the order service.", Audience: "operator"},
		{Module: "billing", Slug: "index", Kind: "faq", Title: "Billing", Body: "Bills for an order.", Audience: "user"},
		{Module: "ghost", Slug: "index", Kind: "guide", Title: "Ghost", Body: "An order nobody serves.", Audience: "user"},
	}, assets: map[string]store.DocAsset{"orders/images/a.png": {Module: "orders", Path: "images/a.png", MIME: "image/png", SHA256: pngSum, Bytes: []byte("\x89PNG")}}}
	s.RegisterDocs(DocsDeps{Reg: reg, Identity: docsIdentity{}, Decide: cd, Store: fd, Roles: []string{"platform-operator"}})
	return s, fd, cd, func(module, mark string) { reg.ApplyMark(context.Background(), module, mark) }
}

var member = map[string]string{"Authorization": "Bearer ok"}

func TestDocsSearchPermissions(t *testing.T) {
	s, fd, cd, mark := docsServer(t)
	for _, tc := range []struct {
		name, who string
		want      []string // module/slug of the hits
		modules   map[string]int
	}{
		{"member sees public pages and what they hold", "ok", []string{"orders/index", "orders/guides/refunds", "billing/index"}, map[string]int{"orders": 2, "billing": 1}},
		{"operator sees operator pages", "op", []string{"orders/index", "orders/guides/refunds", "orders/install", "billing/index"}, map[string]int{"orders": 3, "billing": 1}},
		{"operator role outside the platform tenant is not an operator", "tenant-op", []string{"orders/index", "orders/guides/refunds", "billing/index"}, map[string]int{"orders": 2, "billing": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cd.calls = 0
			w := do(s, "GET", "/gateway/v1/docs/search?q=order", "", map[string]string{"Authorization": "Bearer " + tc.who})
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			var p DocsSearchPage
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, it := range p.Items {
				got = append(got, it.Module+"/"+it.Slug)
			}
			if !slices.Equal(got, tc.want) || p.Total != len(tc.want) || len(p.Facets.Modules) != len(tc.modules) {
				t.Fatalf("got %v total %d facets %v", got, p.Total, p.Facets)
			}
			for m, n := range tc.modules {
				if p.Facets.Modules[m] != n {
					t.Fatalf("facets %v", p.Facets)
				}
			}
			if cd.calls != 1 {
				t.Fatalf("%d Held batches, want 1", cd.calls)
			}
		})
	}
	// The batch carries the qualified requires of the registered modules only.
	sc := fd.scopes[len(fd.scopes)-1]
	if !slices.Equal(sc.Modules, []string{"billing", "orders"}) {
		t.Fatalf("modules in scope: %v (ghost is not registered)", sc.Modules)
	}
	refs := map[string]bool{}
	for _, r := range cd.refs {
		refs[r.String()] = true
	}
	if len(refs) != 2 || !refs["orders:orders:read"] || !refs["orders:orders:admin"] {
		t.Fatalf("refs %v", cd.refs)
	}
	// Facets and filters.
	w := do(s, "GET", "/gateway/v1/docs/search?q=order&module=orders&kind=guide", "", member)
	var p DocsSearchPage
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	if p.Total != 2 || p.Facets.Kinds["guide"] != 2 || p.Items[0].ModuleTitle != "ORDERS" || p.Sort != "rank" || p.Order != "desc" || p.PageSize != 20 {
		t.Fatalf("%s", w.Body.String())
	}
	// Snippets are escaped HTML with <mark> around matches; the summary
	// stands in when the snippet has no match.
	if !strings.Contains(p.Items[0].Snippet, "&lt;b&gt;here&lt;/b&gt;") || !strings.Contains(p.Items[0].Snippet, "<mark>order</mark>") {
		t.Fatalf("%q", p.Items[0].Snippet)
	}
	// A withdrawn or revoked module drops out.
	mark("billing", "revoked")
	p = DocsSearchPage{}
	_ = json.Unmarshal(do(s, "GET", "/gateway/v1/docs/search?q=order", "", member).Body.Bytes(), &p)
	if p.Total != 2 || p.Facets.Modules["billing"] != 0 {
		t.Fatalf("revoked module searched: %+v", p)
	}
}

func TestDocsSearchValidation(t *testing.T) {
	s, _, cd, _ := docsServer(t)
	if w := do(s, "GET", "/gateway/v1/docs/search?q=x", "", nil); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	for _, tc := range []struct{ query, param string }{
		{"", "q"},
		{"q=", "q"},
		{"q=%20%20", "q"},
		{"q=" + strings.Repeat("a", 257), "q"},
		{"q=x&kind=howto", "kind"},
		{"q=x&module=Bad_Name", "module"},
		{"q=x&page_size=51", "page_size"},
		{"q=x&page=0", "page"},
		{"q=x&sort=title", "sort"},
	} {
		w := do(s, "GET", "/gateway/v1/docs/search?"+tc.query, "", member)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"validation_failed"`) {
			t.Errorf("%s → %d %s", tc.query, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"param":"`+tc.param+`"`) && !strings.Contains(w.Body.String(), `"reason":"validation_failed"}`) {
			t.Errorf("%s: %s", tc.query, w.Body.String())
		}
	}
	cd.err = errors.New("down")
	if w := do(s, "GET", "/gateway/v1/docs/search?q=order", "", member); w.Code != 503 {
		t.Fatalf("decision outage → %d", w.Code)
	}
}

func TestSnippetHTML(t *testing.T) {
	for _, tc := range []struct{ snippet, summary, want string }{
		{"a " + store.SnippetStart + "b" + store.SnippetStop + " <c>", "", "a <mark>b</mark> &lt;c&gt;"},
		{"no match <x>", "Sum & more", "Sum &amp; more"},
		{"no match <x>", "", "no match &lt;x&gt;"},
		{store.SnippetStart + "open only", "", "open only"},
		{store.SnippetStop + "x" + store.SnippetStart + "y" + store.SnippetStop, "", "x<mark>y</mark>"},
	} {
		if got := SnippetHTML(tc.snippet, tc.summary); got != tc.want {
			t.Errorf("%q → %q, want %q", tc.snippet, got, tc.want)
		}
	}
}

func TestDocsTree(t *testing.T) {
	s, _, _, _ := docsServer(t)
	w := do(s, "GET", "/gateway/v1/docs/tree", "", member)
	var tree DocsTreeView
	if err := json.Unmarshal(w.Body.Bytes(), &tree); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Modules by title (BILLING, ORDERS), groups by kind, hidden pages absent.
	if len(tree.Modules) != 2 || tree.Modules[0].Module != "billing" || tree.Modules[1].Module != "orders" {
		t.Fatalf("%+v", tree.Modules)
	}
	o := tree.Modules[1]
	if len(o.Groups) != 1 || o.Groups[0].Kind != "guide" || len(o.Groups[0].Pages) != 2 || o.Groups[0].Pages[1].Slug != "guides/refunds" {
		t.Fatalf("%+v", o)
	}
	w = do(s, "GET", "/gateway/v1/docs/tree", "", map[string]string{"Authorization": "Bearer op"})
	_ = json.Unmarshal(w.Body.Bytes(), &tree)
	if g := tree.Modules[1].Groups; len(g) != 2 || g[1].Kind != "reference" || g[1].Pages[0].Slug != "install" {
		t.Fatalf("operator tree %+v", g)
	}
}

func TestDocsPage(t *testing.T) {
	s, _, _, mark := docsServer(t)
	w := do(s, "GET", "/gateway/v1/docs/orders/guides/refunds", "", member)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var p DocPageView
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	if p.Slug != "guides/refunds" || p.Title != "Refunds" || p.ModuleTitle != "ORDERS" || p.Prev == nil || p.Prev.Slug != "index" || p.Next != nil ||
		len(p.Outline) != 1 || p.Outline[0].ID != "steps" || len(p.Tags) != 1 {
		t.Fatalf("%s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"next":null`) || !strings.Contains(w.Body.String(), `"version":""`) {
		t.Fatalf("%s", w.Body.String())
	}
	// Hidden pages look exactly like missing ones.
	missing := do(s, "GET", "/gateway/v1/docs/orders/nope", "", member)
	for _, path := range []string{
		"/gateway/v1/docs/orders/admin",   // requires orders:admin
		"/gateway/v1/docs/orders/install", // operator audience
		"/gateway/v1/docs/ghost/index",    // not registered
		"/gateway/v1/docs/orders/Index",   // not a slug
		"/gateway/v1/docs/orders/a/..%2fb",
	} {
		w := do(s, "GET", path, "", member)
		if w.Code != 404 || w.Body.String() != missing.Body.String() {
			t.Errorf("%s → %d %s", path, w.Code, w.Body.String())
		}
	}
	if w := do(s, "GET", "/gateway/v1/docs/orders/install", "", map[string]string{"Authorization": "Bearer op"}); w.Code != 200 {
		t.Fatalf("operator page → %d", w.Code)
	}
	if w := do(s, "GET", "/gateway/v1/docs/orders/index", "", nil); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	mark("orders", "revoked")
	if w := do(s, "GET", "/gateway/v1/docs/orders/index", "", member); w.Code != 404 {
		t.Fatalf("revoked module → %d", w.Code)
	}
}

func TestDocsAsset(t *testing.T) {
	s, _, _, _ := docsServer(t)
	w := do(s, "GET", "/gateway/v1/docs/orders/assets/images/a.png?v="+pngSum[:16], "", member)
	h := w.Header()
	if w.Code != 200 || h.Get("Content-Type") != "image/png" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("ETag") != `"`+pngSum+`"` ||
		!strings.Contains(h.Get("Cache-Control"), "immutable") || w.Body.String() != "\x89PNG" {
		t.Fatalf("%d %v %q", w.Code, h, w.Body.String())
	}
	if w := do(s, "GET", "/gateway/v1/docs/orders/assets/images/a.png", "", member); w.Header().Get("Cache-Control") != "private, no-cache" {
		t.Fatalf("unversioned URL must revalidate: %v", w.Header())
	}
	if w := do(s, "GET", "/gateway/v1/docs/orders/assets/images/a.png?v=0000000000000000", "", member); strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("a stale version must not be cached forever")
	}
	if w := do(s, "GET", "/gateway/v1/docs/orders/assets/images/a.png", "", map[string]string{"Authorization": "Bearer ok", "If-None-Match": `"` + pngSum + `"`}); w.Code != 304 || w.Body.Len() != 0 {
		t.Fatalf("%d", w.Code)
	}
	for _, path := range []string{"/gateway/v1/docs/orders/assets/images/b.png", "/gateway/v1/docs/ghost/assets/images/a.png", "/gateway/v1/docs/orders/assets/IMAGES/a.png", "/gateway/v1/docs/orders/assets/images/..%2fa.png"} {
		if w := do(s, "GET", path, "", member); w.Code != 404 {
			t.Errorf("%s → %d", path, w.Code)
		}
	}
	if w := do(s, "GET", "/gateway/v1/docs/orders/assets/images/a.png", "", nil); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
}

func TestEventsDocsUpdated(t *testing.T) {
	s, reg, dec, _ := shellServer(t)
	n := &fakeDocsEvents{ch: make(chan string, 1)}
	s.RegisterShell(ShellDeps{Reg: reg, Identity: fakeIdentity{}, Decide: dec, Docs: n})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("GET", "https://localhost/gateway/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer ok")
	rec := newStreamRecorder()
	done := make(chan struct{})
	go func() { s.Handler().ServeHTTP(rec, req); close(done) }()
	n.ch <- "orders"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(rec.String(), "event: docs_updated\ndata: {\"module\":\"orders\"}\n\n") {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if !strings.Contains(rec.String(), "event: docs_updated\ndata: {\"module\":\"orders\"}\n\n") || !n.cancelled {
		t.Fatalf("%q cancelled=%v", rec.String(), n.cancelled)
	}
}

type fakeDocsEvents struct {
	ch        chan string
	cancelled bool
}

func (f *fakeDocsEvents) Subscribe() (<-chan string, func()) {
	return f.ch, func() { f.cancelled = true }
}

type fakeDocsStates struct {
	states []store.DocsState
	err    error
}

func (f fakeDocsStates) DocsStates(context.Context) ([]store.DocsState, error) {
	return f.states, f.err
}

func TestOpsRegistrationsReportDocsState(t *testing.T) {
	s, reg, _, tr := opsServer(t)
	at := time.Date(2026, 10, 15, 1, 2, 3, 0, time.UTC)
	list := func(d DocsStates) string {
		s.RegisterOps(OpsDeps{Reg: reg, Identity: opsIdentity{}, Traffic: tr, Roles: []string{"operator"}, Docs: d})
		w := do(s, "GET", "/gateway/v1/ops/registrations", "", map[string]string{"Authorization": "Bearer operator"})
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	body := list(fakeDocsStates{states: []store.DocsState{{Module: "orders", Digest: "abc", IndexedAt: &at, PageCount: 3, Error: "fetch failed", ErrorAt: &at}}})
	if !strings.Contains(body, `"docs":{"digest":"abc","indexed_at":"2026-10-15T01:02:03Z","page_count":3,"error":"fetch failed","error_at":"2026-10-15T01:02:03Z"}`) {
		t.Fatal(body)
	}
	if body := list(fakeDocsStates{err: errors.New("down")}); strings.Contains(body, `"docs"`) {
		t.Fatalf("store outage: %s", body)
	}
}

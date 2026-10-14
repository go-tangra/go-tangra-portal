//go:build integration

package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// TestModuleDocs covers migration 0009 as gateway_app: replacing a module's
// documentation, failure and removal state, and search: ranking, websearch
// syntax, snippets, the fuzzy fallback and scope filtering with exact totals
// and facets.
func TestModuleDocs(t *testing.T) {
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
	tx := func(fn func(pgx.Tx) error) {
		t.Helper()
		if err := st.Tx(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	ipam := []DocPage{
		{Slug: "index", Kind: "guide", Title: "IPAM", Summary: "Address management.", Body: "Manage networks and addresses.", HTML: "<p>i</p>"},
		{Slug: "subnets", Kind: "guide", Order: 1, Title: "Subnet planning", Summary: "Plan subnets.", Body: "Carve address space into ranges.", HTML: "<p>s</p>",
			Outline: []DocHeading{{ID: "sizes", Text: "Sizes", Level: 2}}, Headings: "Sizes", Tags: []string{"network"}},
		{Slug: "addresses", Kind: "guide", Order: 2, Title: "Allocate addresses", Body: "Pick the next free address in a subnet. Allocation is <atomic> & audited.", HTML: "<p>a</p>"},
		{Slug: "admin", Kind: "reference", Title: "Subnet administration", Body: "Delete a subnet.", Requires: "subnets:admin", HTML: "<p>d</p>"},
		{Slug: "install", Kind: "reference", Title: "Install the subnet service", Body: "Operators install it.", Audience: "operator", HTML: "<p>o</p>"},
		{Slug: "faq", Kind: "faq", Title: "Questions", Body: "Why is my subnet full?", HTML: "<p>f</p>"},
	}
	tx(func(tx pgx.Tx) error {
		if err := ReplaceDocs(ctx, tx, "ipam", "d1", ipam, []DocAsset{{Path: "images/a.png", MIME: "image/png", SHA256: "s1", Bytes: []byte{1, 2}}}, at); err != nil {
			return err // gateway_app needs DML on the docs tables (0009)
		}
		return ReplaceDocs(ctx, tx, "dns", "d9", []DocPage{{Slug: "index", Kind: "guide", Title: "DNS subnet delegation", Body: "Delegate reverse zones per subnet.", HTML: "<p>z</p>"}}, nil, at)
	})

	member := DocsScope{Modules: []string{"ipam", "dns"}}
	admin := DocsScope{Modules: []string{"ipam", "dns"}, Held: []string{"ipam:subnets:admin"}}
	operator := DocsScope{Modules: []string{"ipam", "dns"}, Operator: true}
	withdrawn := DocsScope{Modules: []string{"ipam"}} // dns is not registered
	req, _ := listquery.New(0, 0, "", "", DocsList)
	search := func(s DocsScope, q, module, kind string) DocsResult {
		t.Helper()
		var res DocsResult
		tx(func(tx pgx.Tx) (err error) {
			res, err = SearchDocs(ctx, tx, DocsSearch{Scope: s, Query: q, Module: module, Kind: kind}, req)
			return
		})
		return res
	}
	slugs := func(r DocsResult) []string {
		var out []string
		for _, h := range r.Hits {
			out = append(out, h.Module+"/"+h.Slug)
		}
		return out
	}

	for _, tc := range []struct {
		name            string
		scope           DocsScope
		q, module, kind string
		want            []string // in rank order; nil = only check total/facets
		anyOrder        bool
		total           int
		modules, kinds  map[string]int
		fuzzy           bool
	}{
		{name: "title hit ranks above body hits", scope: member, q: "subnet", total: 4,
			modules: map[string]int{"ipam": 3, "dns": 1}, kinds: map[string]int{"guide": 3, "faq": 1}},
		{name: "requires is honoured in totals and facets", scope: admin, q: "subnet", total: 5,
			modules: map[string]int{"ipam": 4, "dns": 1}, kinds: map[string]int{"guide": 3, "faq": 1, "reference": 1}},
		{name: "operator pages only for operators", scope: operator, q: "install", want: []string{"ipam/install"}, total: 1,
			modules: map[string]int{"ipam": 1}, kinds: map[string]int{"reference": 1}},
		{name: "operator pages hidden from members", scope: member, q: "install service", total: 0, fuzzy: true},
		{name: "withdrawn modules are not searched", scope: withdrawn, q: "delegation", total: 0, fuzzy: true},
		{name: "quoted phrase", scope: member, q: `"next free address"`, want: []string{"ipam/addresses"}, total: 1,
			modules: map[string]int{"ipam": 1}, kinds: map[string]int{"guide": 1}},
		{name: "exclusion", scope: member, q: "subnet -planning -delegation", want: []string{"ipam/addresses", "ipam/faq"}, anyOrder: true, total: 2,
			modules: map[string]int{"ipam": 2}, kinds: map[string]int{"guide": 1, "faq": 1}},
		{name: "kind filter keeps the module facet across kinds of that filter only", scope: member, q: "subnet", kind: "faq", want: []string{"ipam/faq"}, total: 1,
			modules: map[string]int{"ipam": 1}, kinds: map[string]int{"guide": 3, "faq": 1}},
		{name: "module filter", scope: member, q: "subnet", module: "dns", want: []string{"dns/index"}, total: 1,
			modules: map[string]int{"ipam": 3, "dns": 1}, kinds: map[string]int{"guide": 1}},
		{name: "fuzzy fallback on titles", scope: member, q: "subnet planing", want: []string{"ipam/subnets"}, total: 1,
			modules: map[string]int{"ipam": 1}, kinds: map[string]int{"guide": 1}, fuzzy: true},
		{name: "nothing at all", scope: member, q: "kubernetes", total: 0, fuzzy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := search(tc.scope, tc.q, tc.module, tc.kind)
			if r.Total != tc.total || r.Fuzzy != tc.fuzzy || len(r.Hits) != tc.total {
				t.Fatalf("total %d fuzzy %v hits %v", r.Total, r.Fuzzy, slugs(r))
			}
			if tc.modules != nil && (!mapsEqual(r.Module, tc.modules) || !mapsEqual(r.Kinds, tc.kinds)) {
				t.Fatalf("facets %v %v", r.Module, r.Kinds)
			}
			if tc.want != nil {
				got := slugs(r)
				if tc.anyOrder {
					slices.Sort(got)
				}
				if !slices.Equal(got, tc.want) {
					t.Fatalf("hits %v want %v", got, tc.want)
				}
			}
		})
	}
	// Title hits (weight A) rank above body-only hits (weight C).
	r := search(member, "subnet", "", "")
	top := slugs(r)[:2]
	slices.Sort(top)
	if !slices.Equal(top, []string{"dns/index", "ipam/subnets"}) || r.Hits[1].Rank <= r.Hits[2].Rank {
		t.Fatalf("title hits must rank first: %+v", r.Hits)
	}
	for _, h := range r.Hits {
		if h.Slug == "addresses" && (!strings.Contains(h.Snippet, SnippetStart+"subnet"+SnippetStop) || !strings.Contains(h.Snippet, "<atomic>")) {
			t.Fatalf("snippet (marked, not escaped by the store): %q", h.Snippet)
		}
	}
	// Paging past the end clamps to the last page.
	far, _ := listquery.New(9, 2, "", "", DocsList)
	tx(func(tx pgx.Tx) error {
		res, err := SearchDocs(ctx, tx, DocsSearch{Scope: member, Query: "subnet"}, far)
		if err != nil || res.Req.Page != 2 || len(res.Hits) != 2 || res.Total != 4 {
			t.Fatalf("%+v %v", res, err)
		}
		return nil
	})

	// Tree, page, requires, assets.
	tx(func(tx pgx.Tx) error {
		tree, err := DocsTree(ctx, tx, member)
		if err != nil {
			return err
		}
		var got []string
		for _, e := range tree {
			got = append(got, e.Module+"/"+e.Slug)
		}
		if !slices.Equal(got, []string{"dns/index", "ipam/index", "ipam/subnets", "ipam/addresses", "ipam/faq"}) {
			t.Fatalf("tree %v", got)
		}
		p, err := GetDoc(ctx, tx, member, "ipam", "subnets")
		if err != nil || p.Title != "Subnet planning" || len(p.Outline) != 1 || p.Outline[0].ID != "sizes" || p.Tags[0] != "network" || p.Digest != "d1" {
			t.Fatalf("%+v %v", p, err)
		}
		for _, hidden := range []string{"admin", "install", "missing"} {
			if _, err := GetDoc(ctx, tx, member, "ipam", hidden); !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: %v", hidden, err)
			}
		}
		if _, err := GetDoc(ctx, tx, withdrawn, "dns", "index"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("withdrawn: %v", err)
		}
		req, err := DocsRequires(ctx, tx, []string{"ipam", "dns"})
		if err != nil || len(req) != 1 || !slices.Equal(req["ipam"], []string{"subnets:admin"}) {
			t.Fatalf("%v %v", req, err)
		}
		a, err := GetDocAsset(ctx, tx, "ipam", "images/a.png")
		if err != nil || a.MIME != "image/png" || a.SHA256 != "s1" || len(a.Bytes) != 2 {
			t.Fatalf("%+v %v", a, err)
		}
		if _, err := GetDocAsset(ctx, tx, "ipam", "images/b.png"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		return nil
	})

	// State: failure keeps the index, success replaces it, removal clears all.
	state := func(m string) (DocsState, error) {
		var s DocsState
		err := st.Tx(ctx, func(tx pgx.Tx) (err error) { s, err = GetDocsState(ctx, tx, m); return })
		return s, err
	}
	tx(func(tx pgx.Tx) error { return DocsFailed(ctx, tx, "ipam", "fetch: refused", at) })
	if s, err := state("ipam"); err != nil || s.Digest != "d1" || s.Error != "fetch: refused" || s.PageCount != 6 || s.IndexedAt == nil || s.ErrorAt == nil {
		t.Fatalf("%+v %v", s, err)
	}
	tx(func(tx pgx.Tx) error { return DocsFailed(ctx, tx, "new", "first fetch failed", at) })
	if s, err := state("new"); err != nil || s.Digest != "" || s.Error == "" {
		t.Fatalf("%+v %v", s, err)
	}
	tx(func(tx pgx.Tx) error { return ClearDocsError(ctx, tx, "new") })
	if s, _ := state("new"); s.Error != "" {
		t.Fatalf("%+v", s)
	}
	tx(func(tx pgx.Tx) error { return ReplaceDocs(ctx, tx, "ipam", "d2", ipam[:1], nil, at) })
	if s, _ := state("ipam"); s.Digest != "d2" || s.Error != "" || s.PageCount != 1 {
		t.Fatalf("%+v", s)
	}
	if r := search(member, "subnet", "ipam", ""); r.Total != 0 {
		t.Fatalf("old pages survived a replace: %v", slugs(r))
	}
	tx(func(tx pgx.Tx) error {
		if _, err := GetDocAsset(ctx, tx, "ipam", "images/a.png"); !errors.Is(err, ErrNotFound) {
			t.Fatal("old asset survived a replace")
		}
		return RemoveDocs(ctx, tx, "ipam")
	})
	if _, err := state("ipam"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	var states []DocsState
	tx(func(tx pgx.Tx) (err error) { states, err = ListDocsStates(ctx, tx); return })
	if len(states) != 2 || states[0].Module != "dns" || states[1].Module != "new" {
		t.Fatalf("%+v", states)
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

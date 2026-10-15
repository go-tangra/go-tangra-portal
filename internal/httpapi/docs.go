package httpapi

import (
	"context"
	"errors"
	"html"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/go-tangra/go-tangra-portal/v4/internal/authz"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/listquery"
)

// DocsReader is the documentation store the help API reads.
type DocsReader interface {
	DocsRequires(ctx context.Context, modules []string) (map[string][]string, error)
	SearchDocs(ctx context.Context, q store.DocsSearch, req listquery.Request) (store.DocsResult, error)
	DocsTree(ctx context.Context, s store.DocsScope) ([]store.DocEntry, error)
	GetDoc(ctx context.Context, s store.DocsScope, module, slug string) (store.DocPage, error)
	GetDocAsset(ctx context.Context, module, path string) (store.DocAsset, error)
}

// DocsDeps wire the help (module documentation) API.
type DocsDeps struct {
	Reg      *registry.Registry
	Identity IdentitySource
	Decide   Decisions
	Store    DocsReader
	// Roles are the platform operator roles: operator-audience pages are
	// shown only to platform operators holding one.
	Roles []string
}

// MaxDocsQuery bounds the search text (characters).
const MaxDocsQuery = 256

// DocKinds are the page kinds in display order.
var DocKinds = []string{"guide", "example", "reference", "faq"}

var (
	docsModuleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	docsSlugRE   = regexp.MustCompile(`^[a-z0-9-]+(/[a-z0-9-]+)*$`)
	docsAssetRE  = regexp.MustCompile(`^[a-z0-9_.-]+(/[a-z0-9_.-]+)*$`)
)

// DocHitView is one search result.
type DocHitView struct {
	Module      string `json:"module"`
	ModuleTitle string `json:"module_title"`
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	Kind        string `json:"kind"`
	// Snippet is HTML: the matched text escaped, matches wrapped in <mark>.
	Snippet string  `json:"snippet"`
	Rank    float64 `json:"rank"`
}

// DocsFacets count the hits per module and per kind.
type DocsFacets struct {
	Modules map[string]int `json:"modules"`
	Kinds   map[string]int `json:"kinds"`
}

// DocsSearchPage is the GET /gateway/v1/docs/search body: the list contract
// plus facets.
type DocsSearchPage struct {
	Items    []DocHitView  `json:"items"`
	Total    int           `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
	Sort     string        `json:"sort"`
	Order    listquery.Dir `json:"order"`
	Facets   DocsFacets    `json:"facets"`
	// Fuzzy is set when nothing matched the text search and the items are
	// titles similar to the query instead.
	Fuzzy bool `json:"fuzzy"`
}

// DocsTreeView is the GET /gateway/v1/docs/tree body.
type DocsTreeView struct {
	Modules []DocsModuleView `json:"modules"`
}

// DocsModuleView is a module with its visible pages grouped by kind.
type DocsModuleView struct {
	Module string          `json:"module"`
	Title  string          `json:"title"`
	Icon   string          `json:"icon,omitempty"`
	Groups []DocsGroupView `json:"groups"`
}

// DocsGroupView is the pages of one kind, by order then title.
type DocsGroupView struct {
	Kind  string         `json:"kind"`
	Pages []DocEntryView `json:"pages"`
}

// DocEntryView is a page in the tree.
type DocEntryView struct {
	Slug    string `json:"slug"`
	Title   string `json:"title"`
	Summary string `json:"summary,omitempty"`
}

// DocLinkView names a neighbouring page.
type DocLinkView struct {
	Slug  string `json:"slug"`
	Title string `json:"title"`
}

// DocPageView is the GET /gateway/v1/docs/{module}/{slug} body.
type DocPageView struct {
	Module      string             `json:"module"`
	ModuleTitle string             `json:"module_title"`
	Slug        string             `json:"slug"`
	Title       string             `json:"title"`
	Summary     string             `json:"summary"`
	Kind        string             `json:"kind"`
	Tags        []string           `json:"tags"`
	HTML        string             `json:"html"`
	Outline     []store.DocHeading `json:"outline"`
	Prev        *DocLinkView       `json:"prev"`
	Next        *DocLinkView       `json:"next"`
	// Version is the newest release the module's instances run.
	Version string `json:"version"`
}

// RegisterDocs mounts the help API.
func (s *Server) RegisterDocs(d DocsDeps) {
	s.MustHandle("GET", "/gateway/v1/docs/search", s.docsSearch(d))
	s.MustHandle("GET", "/gateway/v1/docs/tree", s.docsTree(d))
	s.MustHandle("GET", "/gateway/v1/docs/{module}/{slug}", s.docsPage(d))
	s.MustHandle("GET", "/gateway/v1/docs/{module}/assets/{path}", s.docsAsset(d))
}

// docsScope is what the caller may see among regs: one Held batch for the
// distinct page requires of those modules (qualified with the module, as nav
// requires are), operator pages only for platform operators.
func docsScope(ctx context.Context, d DocsDeps, id identity.Identity, regs []registry.Registration) (store.DocsScope, error) {
	sc := store.DocsScope{Modules: []string{}, Held: []string{}, Operator: IsOperator(id, d.Roles)}
	for _, reg := range regs {
		sc.Modules = append(sc.Modules, reg.Module)
	}
	if len(sc.Modules) == 0 {
		return sc, nil
	}
	requires, err := d.Store.DocsRequires(ctx, sc.Modules)
	if err != nil {
		return sc, err
	}
	var refs []authz.Ref
	for m, perms := range requires {
		for _, p := range perms {
			refs = append(refs, authz.Ref{Module: m, Perm: p})
		}
	}
	if len(refs) == 0 {
		return sc, nil
	}
	held, err := d.Decide.Held(ctx, id.TenantID, id.UserID, refs)
	if err != nil {
		return sc, err
	}
	for ref, ok := range held {
		if ok {
			sc.Held = append(sc.Held, ref.String())
		}
	}
	sort.Strings(sc.Held)
	return sc, nil
}

// docsModule is a visible registration by name.
func docsModule(reg *registry.Registry, module string) (registry.Registration, bool) {
	if !docsModuleRE.MatchString(module) {
		return registry.Registration{}, false
	}
	r, ok := reg.Get(module)
	if !ok || reg.State(module) == registry.StateRevoked {
		return registry.Registration{}, false
	}
	return r, true
}

func (s *Server) docsSearch(d DocsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireIdentity(w, r, d.Identity, s.rt.Logger())
		if !ok {
			return
		}
		q := r.URL.Query()
		text := strings.TrimSpace(q.Get("q"))
		if text == "" || utf8.RuneCountInString(text) > MaxDocsQuery || !utf8.ValidString(text) {
			failParam(w, "q")
			return
		}
		module, kind := q.Get("module"), q.Get("kind")
		if module != "" && !docsModuleRE.MatchString(module) {
			failParam(w, "module")
			return
		}
		if kind != "" && !validKind(kind) {
			failParam(w, "kind")
			return
		}
		req, ok := parseList(w, r, store.DocsList)
		if !ok {
			return
		}
		regs := visible(d.Reg)
		titles := map[string]string{}
		for _, reg := range regs {
			titles[reg.Module] = moduleTitle(reg)
		}
		sc, err := docsScope(r.Context(), d, id, regs)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		res, err := d.Store.SearchDocs(r.Context(), store.DocsSearch{Scope: sc, Query: text, Module: module, Kind: kind}, req)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		out := DocsSearchPage{Items: make([]DocHitView, 0, len(res.Hits)), Total: res.Total, Page: res.Req.Page, PageSize: res.Req.PageSize,
			Sort: res.Req.Sort, Order: res.Req.Order, Facets: DocsFacets{Modules: nonNilCounts(res.Module), Kinds: nonNilCounts(res.Kinds)}, Fuzzy: res.Fuzzy}
		for _, h := range res.Hits {
			out.Items = append(out.Items, DocHitView{Module: h.Module, ModuleTitle: titles[h.Module], Slug: h.Slug, Title: h.Title, Kind: h.Kind,
				Snippet: SnippetHTML(h.Snippet, h.Summary), Rank: h.Rank})
		}
		WriteJSON(w, http.StatusOK, out)
	}
}

// SnippetHTML escapes a ts_headline result and turns its markers into
// <mark>; without any match in it the escaped summary is used instead.
func SnippetHTML(snippet, summary string) string {
	if !strings.Contains(snippet, store.SnippetStart) && summary != "" {
		return html.EscapeString(summary)
	}
	// Stray markers (never in indexed text) cannot unbalance the markup:
	// only complete pairs become <mark>.
	esc := html.EscapeString(snippet)
	var b strings.Builder
	for {
		i := strings.Index(esc, store.SnippetStart)
		if i < 0 {
			break
		}
		j := strings.Index(esc[i:], store.SnippetStop)
		if j < 0 {
			break
		}
		b.WriteString(esc[:i])
		b.WriteString("<mark>")
		b.WriteString(esc[i+len(store.SnippetStart) : i+j])
		b.WriteString("</mark>")
		esc = esc[i+j+len(store.SnippetStop):]
	}
	b.WriteString(esc)
	return strings.NewReplacer(store.SnippetStart, "", store.SnippetStop, "").Replace(b.String())
}

func (s *Server) docsTree(d DocsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireIdentity(w, r, d.Identity, s.rt.Logger())
		if !ok {
			return
		}
		regs := visible(d.Reg)
		sc, err := docsScope(r.Context(), d, id, regs)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		entries, err := d.Store.DocsTree(r.Context(), sc)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		byModule := map[string]*DocsModuleView{}
		out := DocsTreeView{Modules: []DocsModuleView{}}
		var order []string
		for _, reg := range regs {
			byModule[reg.Module] = &DocsModuleView{Module: reg.Module, Title: moduleTitle(reg), Icon: moduleIcon(reg), Groups: []DocsGroupView{}}
		}
		for _, e := range entries {
			m := byModule[e.Module]
			if m == nil {
				continue
			}
			if len(m.Groups) == 0 {
				order = append(order, e.Module)
			}
			if n := len(m.Groups); n == 0 || m.Groups[n-1].Kind != e.Kind {
				m.Groups = append(m.Groups, DocsGroupView{Kind: e.Kind, Pages: []DocEntryView{}})
			}
			g := &m.Groups[len(m.Groups)-1]
			g.Pages = append(g.Pages, DocEntryView{Slug: e.Slug, Title: e.Title, Summary: e.Summary})
		}
		for _, name := range order {
			out.Modules = append(out.Modules, *byModule[name])
		}
		sort.SliceStable(out.Modules, func(i, j int) bool {
			return strings.ToLower(out.Modules[i].Title) < strings.ToLower(out.Modules[j].Title)
		})
		WriteJSON(w, http.StatusOK, out)
	}
}

func (s *Server) docsPage(d DocsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireIdentity(w, r, d.Identity, s.rt.Logger())
		if !ok {
			return
		}
		module, slug := r.PathValue("module"), r.PathValue("slug")
		reg, found := docsModule(d.Reg, module)
		if !found || len(slug) > 256 || !docsSlugRE.MatchString(slug) {
			WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
			return
		}
		sc, err := docsScope(r.Context(), d, id, []registry.Registration{reg})
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		// Hidden and missing pages look the same: 404, never 403.
		p, err := d.Store.GetDoc(r.Context(), sc, module, slug)
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
			return
		}
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		v := DocPageView{Module: module, ModuleTitle: moduleTitle(reg), Slug: p.Slug, Title: p.Title, Summary: p.Summary, Kind: p.Kind,
			Tags: nonNil(p.Tags), HTML: p.HTML, Outline: p.Outline}
		if v.Outline == nil {
			v.Outline = []store.DocHeading{}
		}
		if builds := reg.BuildVersions(); len(builds) > 0 {
			v.Version = builds[len(builds)-1]
		}
		// Neighbours follow the tree order (kind, order, title) within what
		// the caller may see.
		entries, err := d.Store.DocsTree(r.Context(), sc)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		for i, e := range entries {
			if e.Slug != p.Slug {
				continue
			}
			if i > 0 {
				v.Prev = &DocLinkView{Slug: entries[i-1].Slug, Title: entries[i-1].Title}
			}
			if i+1 < len(entries) {
				v.Next = &DocLinkView{Slug: entries[i+1].Slug, Title: entries[i+1].Title}
			}
			break
		}
		WriteJSON(w, http.StatusOK, v)
	}
}

func (s *Server) docsAsset(d DocsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireIdentity(w, r, d.Identity, s.rt.Logger()); !ok {
			return
		}
		module, p := r.PathValue("module"), r.PathValue("path")
		_, found := docsModule(d.Reg, module)
		if !found || len(p) > 512 || !docsAssetRE.MatchString(p) || strings.Contains("/"+p+"/", "/../") || strings.Contains("/"+p+"/", "/./") {
			WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
			return
		}
		a, err := d.Store.GetDocAsset(r.Context(), module, p)
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
			return
		}
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		h := w.Header()
		etag := `"` + a.SHA256 + `"`
		h.Set("ETag", etag)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
		// Rendered pages reference assets with ?v=<sha256 prefix>: such a URL
		// names one content forever. Without it, revalidate.
		if v := r.URL.Query().Get("v"); v != "" && len(v) >= 16 && strings.HasPrefix(a.SHA256, v) {
			h.Set("Cache-Control", "private, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "private, no-cache")
		}
		if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		h.Set("Content-Type", a.MIME)
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(a.Bytes)
		}
	}
}

// moduleTitle is the module's display name (its name when it has none).
func moduleTitle(reg registry.Registration) string {
	if reg.Manifest.DisplayName != "" {
		return reg.Manifest.DisplayName
	}
	return reg.Module
}

// moduleIcon is the icon of the module's first navigation entry (by order)
// that has one: manifests carry no module-level icon.
func moduleIcon(reg registry.Registration) string {
	nav := append([]manifest.NavEntry(nil), reg.Manifest.Nav...)
	sort.SliceStable(nav, func(i, j int) bool { return nav[i].Order < nav[j].Order })
	for _, n := range nav {
		if n.Icon != "" {
			return n.Icon
		}
	}
	return ""
}

func validKind(k string) bool {
	for _, v := range DocKinds {
		if v == k {
			return true
		}
	}
	return false
}

func nonNilCounts(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// DocPage is one rendered help page of a module (module_docs).
type DocPage struct {
	Module   string
	Slug     string
	Lang     string // "en" (default) → english text search; anything else → simple
	Kind     string
	Audience string // user | operator
	Title    string
	Summary  string
	Tags     []string
	Requires string // module-local resource:action; "" = everyone
	Order    int
	Headings string // h2/h3 text, for search
	Outline  []DocHeading
	Body     string // plain text, for search and snippets
	HTML     string // rendered and sanitized
	Digest   string
}

// DocHeading is one entry of a page outline.
type DocHeading struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Level int    `json:"level"`
}

// DocAsset is an image referenced by a module's pages (module_doc_assets).
type DocAsset struct {
	Module string
	Path   string
	MIME   string
	SHA256 string
	Bytes  []byte
}

// DocsState is what is indexed for a module (module_docs_state).
type DocsState struct {
	Module    string
	Digest    string // indexed bundle; "" before the first success
	IndexedAt *time.Time
	Error     string // last failure, "" after a success
	ErrorAt   *time.Time
	PageCount int
}

// DocsScope is what a caller may see: pages of Modules whose requires is
// empty or in Held ("module:resource:action"), operator pages only for
// operators.
type DocsScope struct {
	Modules  []string
	Held     []string
	Operator bool
}

// DocsSearch is a full-text search within a scope; Module and Kind narrow it
// ("" = all).
type DocsSearch struct {
	Scope  DocsScope
	Query  string
	Module string
	Kind   string
}

// DocHit is one search result.
type DocHit struct {
	Module  string
	Slug    string
	Title   string
	Kind    string
	Summary string
	Snippet string // ts_headline with SnippetStart/SnippetStop marks, not escaped
	Rank    float64
}

// DocsResult is a page of hits with exact totals and facets. Each facet
// ignores its own filter (modules counts across kinds when kind narrows the
// search and vice versa) so a UI can offer the alternatives. Fuzzy is set when
// no page matched the text search and the hits come from trigram similarity on
// titles.
type DocsResult struct {
	Hits   []DocHit
	Total  int
	Req    listquery.Request
	Module map[string]int
	Kinds  map[string]int
	Fuzzy  bool
}

// DocEntry is a page in the help tree (no content).
type DocEntry struct {
	Module  string
	Slug    string
	Title   string
	Summary string
	Kind    string
	Order   int
}

// Snippet markers: private-use code points that never occur in an indexed
// body (the indexer strips U+E000..U+E0FF), replaced by <mark> after HTML
// escaping.
const (
	SnippetStart = ""
	SnippetStop  = ""
)

// The text-search parser treats <...> as markup and drops it, but indexed
// text is plain text ("List<T>"): angle brackets are swapped for private-use
// code points while indexing and highlighting, and swapped back in snippets.
const (
	markLT = "\uE002"
	markGT = "\uE003"
)

// plainSQL wraps a text expression so the parser sees no markup.
func plainSQL(expr string) string {
	return "translate(" + expr + ", '<>', '" + markLT + markGT + "')"
}

var unmark = strings.NewReplacer(markLT, "<", markGT, ">")

// splitSQL turns '.' and '_' into spaces. The parser keeps "jobs.lease_seconds"
// as the host-like token "jobs.lease" plus "seconds", so a search for
// "lease_seconds" or "lease" would miss it; a split copy of the text, at the
// lowest weight, makes the parts of dotted and snake_case identifiers
// searchable while the whole identifier still matches the original tokens.
func splitSQL(expr string) string {
	return "translate(" + expr + ", '._', '  ')"
}

// DocsList pages search hits by relevance.
var DocsList = listquery.Spec{
	Fields:   map[string]listquery.Field{"rank": {Expr: "rank", DefaultDir: listquery.Desc, NotNull: true}},
	Default:  "rank",
	TieBreak: "(module || '/' || slug)",
	MaxSize:  50, DefaultSize: 20,
}

// textConfig is the text-search configuration for a page language.
func textConfig(lang string) string {
	if lang == "" || lang == "en" {
		return "english"
	}
	return "simple"
}

// ReplaceDocs replaces a module's pages and assets with a new bundle and
// records it as indexed (error cleared). Run it in one transaction.
func ReplaceDocs(ctx context.Context, tx pgx.Tx, module, digest string, pages []DocPage, assets []DocAsset, at time.Time) error {
	if _, err := tx.Exec(ctx, `DELETE FROM module_docs WHERE module = $1`, module); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM module_doc_assets WHERE module = $1`, module); err != nil {
		return err
	}
	for i := range pages {
		p := &pages[i]
		lang := p.Lang
		if lang == "" {
			lang = "en"
		}
		audience := p.Audience
		if audience == "" {
			audience = "user"
		}
		tags := p.Tags
		if tags == nil {
			tags = []string{}
		}
		outline := p.Outline
		if outline == nil {
			outline = []DocHeading{}
		}
		ol, err := json.Marshal(outline)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO module_docs (module, slug, lang, kind, audience, title, summary, tags, requires, ord, headings, outline, body, html, digest, updated_at, tsv)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
  setweight(to_tsvector($17::regconfig, `+plainSQL("$6")+`), 'A') ||
  setweight(to_tsvector($17::regconfig, `+plainSQL("$7 || ' ' || array_to_string($8::text[], ' ') || ' ' || $11")+`), 'B') ||
  setweight(to_tsvector($17::regconfig, `+plainSQL("$13")+`), 'C') ||
  setweight(to_tsvector($17::regconfig, `+plainSQL(splitSQL("$6 || ' ' || $7 || ' ' || $11 || ' ' || $13"))+`), 'D'))`,
			module, p.Slug, lang, p.Kind, audience, p.Title, p.Summary, tags, nullable(p.Requires), p.Order, p.Headings, ol, p.Body, p.HTML, digest, at, textConfig(lang)); err != nil {
			return err
		}
	}
	for i := range assets {
		a := &assets[i]
		if _, err := tx.Exec(ctx, `INSERT INTO module_doc_assets (module, path, mime, sha256, bytes) VALUES ($1,$2,$3,$4,$5)`,
			module, a.Path, a.MIME, a.SHA256, a.Bytes); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO module_docs_state (module, digest, indexed_at, error, error_at, page_count) VALUES ($1,$2,$3,NULL,NULL,$4)
ON CONFLICT (module) DO UPDATE SET digest = EXCLUDED.digest, indexed_at = EXCLUDED.indexed_at, error = NULL, error_at = NULL, page_count = EXCLUDED.page_count`,
		module, digest, at, len(pages))
	return err
}

// RemoveDocs deletes a module's pages, assets and state (it ships no docs).
func RemoveDocs(ctx context.Context, tx pgx.Tx, module string) error {
	for _, q := range []string{`DELETE FROM module_docs WHERE module = $1`, `DELETE FROM module_doc_assets WHERE module = $1`, `DELETE FROM module_docs_state WHERE module = $1`} {
		if _, err := tx.Exec(ctx, q, module); err != nil {
			return err
		}
	}
	return nil
}

// DocsFailed records a failed fetch or index; the indexed pages stay.
func DocsFailed(ctx context.Context, tx pgx.Tx, module, errText string, at time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO module_docs_state (module, error, error_at) VALUES ($1,$2,$3)
ON CONFLICT (module) DO UPDATE SET error = EXCLUDED.error, error_at = EXCLUDED.error_at`, module, errText, at)
	return err
}

// ClearDocsError forgets a failure (the wanted bundle is the indexed one again).
func ClearDocsError(ctx context.Context, tx pgx.Tx, module string) error {
	_, err := tx.Exec(ctx, `UPDATE module_docs_state SET error = NULL, error_at = NULL WHERE module = $1`, module)
	return err
}

// GetDocsState reads one module's state (ErrNotFound when none).
func GetDocsState(ctx context.Context, tx pgx.Tx, module string) (DocsState, error) {
	s := DocsState{}
	var errText *string
	err := tx.QueryRow(ctx, `SELECT module, digest, indexed_at, error, error_at, page_count FROM module_docs_state WHERE module = $1`, module).
		Scan(&s.Module, &s.Digest, &s.IndexedAt, &errText, &s.ErrorAt, &s.PageCount)
	if errText != nil {
		s.Error = *errText
	}
	return s, notFound(err)
}

// ListDocsStates reads every module's state, by module.
func ListDocsStates(ctx context.Context, tx pgx.Tx) ([]DocsState, error) {
	rows, err := tx.Query(ctx, `SELECT module, digest, indexed_at, error, error_at, page_count FROM module_docs_state ORDER BY module`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DocsState
	for rows.Next() {
		var s DocsState
		var errText *string
		if err := rows.Scan(&s.Module, &s.Digest, &s.IndexedAt, &errText, &s.ErrorAt, &s.PageCount); err != nil {
			return nil, err
		}
		if errText != nil {
			s.Error = *errText
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DocsRequires lists the distinct non-empty requires of the modules' pages.
func DocsRequires(ctx context.Context, tx pgx.Tx, modules []string) (map[string][]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT module, requires FROM module_docs WHERE module = ANY($1) AND requires IS NOT NULL ORDER BY module, requires`, modules)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var m, r string
		if err := rows.Scan(&m, &r); err != nil {
			return nil, err
		}
		out[m] = append(out[m], r)
	}
	return out, rows.Err()
}

// scopeSQL filters module_docs (alias d) to a scope; $1 modules, $2 held,
// $3 operator.
const scopeSQL = `d.module = ANY($1::text[]) AND (d.requires IS NULL OR (d.module || ':' || d.requires) = ANY($2::text[])) AND (d.audience = 'user' OR $3::boolean)`

func scopeArgs(s DocsScope) []any {
	mods, held := s.Modules, s.Held
	if mods == nil {
		mods = []string{}
	}
	if held == nil {
		held = []string{}
	}
	return []any{mods, held, s.Operator}
}

// SearchDocs runs a websearch-syntax full-text query within a scope, ranked
// by ts_rank_cd; when nothing matches it falls back to trigram word
// similarity on titles. Totals and facets count only pages in scope.
func SearchDocs(ctx context.Context, tx pgx.Tx, q DocsSearch, req listquery.Request) (DocsResult, error) {
	res, err := searchDocs(ctx, tx, q, req, false)
	if err != nil || res.Total > 0 || len(res.Module) > 0 || len(res.Kinds) > 0 {
		return res, err
	}
	return searchDocs(ctx, tx, q, req, true)
}

// Full-text and fuzzy matching. $4 is the query text. The text search keeps
// the language split visible to the planner so both branches can use the
// GIN index on tsv; fuzzy matching uses the trigram index on title.
const (
	ftsHits = `SELECT d.module, d.slug, d.title, d.kind, d.summary, d.body, d.lang,
  ts_rank_cd(d.tsv, CASE WHEN d.lang = 'en' THEN websearch_to_tsquery('english', $4) ELSE websearch_to_tsquery('simple', $4) END) AS rank
FROM module_docs d
WHERE ((d.lang = 'en' AND d.tsv @@ websearch_to_tsquery('english', $4)) OR (d.lang <> 'en' AND d.tsv @@ websearch_to_tsquery('simple', $4)))
  AND ` + scopeSQL
	fuzzyHits = `SELECT d.module, d.slug, d.title, d.kind, d.summary, d.body, d.lang,
  word_similarity($4, d.title)::float8 AS rank
FROM module_docs d
WHERE $4 <% d.title AND ` + scopeSQL
)

func searchDocs(ctx context.Context, tx pgx.Tx, q DocsSearch, req listquery.Request, fuzzy bool) (DocsResult, error) {
	hits := ftsHits
	if fuzzy {
		hits = fuzzyHits
	}
	args := append(scopeArgs(q.Scope), q.Query)
	res := DocsResult{Module: map[string]int{}, Kinds: map[string]int{}, Fuzzy: fuzzy}
	rows, err := tx.Query(ctx, `WITH hits AS (`+hits+`) SELECT module, kind, count(*) FROM hits GROUP BY module, kind`, args...)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		var m, k string
		var n int
		if err := rows.Scan(&m, &k, &n); err != nil {
			rows.Close()
			return res, err
		}
		if q.Kind == "" || q.Kind == k {
			res.Module[m] += n
		}
		if q.Module == "" || q.Module == m {
			res.Kinds[k] += n
		}
		if (q.Kind == "" || q.Kind == k) && (q.Module == "" || q.Module == m) {
			res.Total += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	req = req.Clamp(res.Total)
	res.Req = req
	if res.Total == 0 {
		return res, nil
	}
	snippet := `ts_headline(CASE WHEN lang = 'en' THEN 'english'::regconfig ELSE 'simple'::regconfig END, ` + plainSQL("body") + `,
  CASE WHEN lang = 'en' THEN websearch_to_tsquery('english', $4) ELSE websearch_to_tsquery('simple', $4) END,
  'StartSel=` + SnippetStart + `, StopSel=` + SnippetStop + `, MaxWords=30, MinWords=12, MaxFragments=2, FragmentDelimiter=" … "')`
	if fuzzy {
		snippet = `''`
	}
	page, err := tx.Query(ctx, `WITH hits AS (`+hits+`)
SELECT module, slug, title, kind, summary, `+snippet+`, rank FROM hits
WHERE ($5 = '' OR module = $5) AND ($6 = '' OR kind = $6)
ORDER BY `+req.OrderBy(DocsList)+` LIMIT $7 OFFSET $8`, append(args, q.Module, q.Kind, req.Limit(), req.Offset())...)
	if err != nil {
		return res, err
	}
	defer page.Close()
	for page.Next() {
		var h DocHit
		if err := page.Scan(&h.Module, &h.Slug, &h.Title, &h.Kind, &h.Summary, &h.Snippet, &h.Rank); err != nil {
			return res, err
		}
		h.Snippet = unmark.Replace(h.Snippet)
		res.Hits = append(res.Hits, h)
	}
	return res, page.Err()
}

// DocsTree lists the pages in scope (no content), by module, kind, order,
// title.
func DocsTree(ctx context.Context, tx pgx.Tx, s DocsScope) ([]DocEntry, error) {
	rows, err := tx.Query(ctx, `SELECT d.module, d.slug, d.title, d.summary, d.kind, d.ord FROM module_docs d WHERE d.lang = 'en' AND `+scopeSQL+`
ORDER BY d.module, array_position(ARRAY['guide','example','reference','faq'], d.kind), d.ord, lower(d.title), d.slug`, scopeArgs(s)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DocEntry
	for rows.Next() {
		var e DocEntry
		if err := rows.Scan(&e.Module, &e.Slug, &e.Title, &e.Summary, &e.Kind, &e.Order); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetDoc reads one page in scope (ErrNotFound when it does not exist or the
// scope hides it).
func GetDoc(ctx context.Context, tx pgx.Tx, s DocsScope, module, slug string) (DocPage, error) {
	var p DocPage
	var requires *string
	var outline []byte
	err := tx.QueryRow(ctx, `SELECT d.module, d.slug, d.lang, d.kind, d.audience, d.title, d.summary, d.tags, d.requires, d.ord, d.outline, d.html, d.digest
FROM module_docs d WHERE d.module = $4 AND d.slug = $5 AND d.lang = 'en' AND `+scopeSQL, append(scopeArgs(s), module, slug)...).
		Scan(&p.Module, &p.Slug, &p.Lang, &p.Kind, &p.Audience, &p.Title, &p.Summary, &p.Tags, &requires, &p.Order, &outline, &p.HTML, &p.Digest)
	if err != nil {
		return p, notFound(err)
	}
	if requires != nil {
		p.Requires = *requires
	}
	if err := json.Unmarshal(outline, &p.Outline); err != nil {
		return p, err
	}
	return p, nil
}

// GetDocAsset reads one asset (ErrNotFound when missing).
func GetDocAsset(ctx context.Context, tx pgx.Tx, module, path string) (DocAsset, error) {
	a := DocAsset{Module: module, Path: path}
	err := tx.QueryRow(ctx, `SELECT mime, sha256, bytes FROM module_doc_assets WHERE module = $1 AND path = $2`, module, path).Scan(&a.MIME, &a.SHA256, &a.Bytes)
	return a, notFound(err)
}

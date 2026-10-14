package docs

import (
	"bytes"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/alecthomas/chroma/v2"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// Console routes the rendered HTML links to. PageRoute is the shell's help
// page route (/help/<module>/<slug>); AssetRoute serves bundle images
// (/gateway/v1/docs/<module>/assets/<path>).
const (
	PageRoute  = "/help/"
	AssetRoute = "/gateway/v1/docs/"
)

// Rendered is a page turned into sanitized HTML plus its search text.
type Rendered struct {
	HTML     string
	Outline  []store.DocHeading // h2/h3 with their ids
	Headings string             // outline text, for search
	Body     string             // plain text of the whole page, for search and snippets
}

// Site is what link rewriting needs to know about the module's bundle.
type Site struct {
	Module string
	Pages  map[string]bool   // slugs
	Assets map[string]string // path → sha256
}

// policy is the sanitizer allow-list: Markdown output only, no raw HTML
// survives the renderer anyway; no style attributes, scripts, frames or
// forms; links http/https/mailto or relative; code classes for highlighting.
var policy = func() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowStandardURLs() // parseable; relative, http, https, mailto
	p.AllowElements("p", "br", "hr", "blockquote", "ul", "li", "dl", "dt", "dd", "table", "thead", "tbody", "tfoot", "tr",
		"em", "strong", "del", "s", "sup", "sub", "kbd", "b", "i")
	p.AllowAttrs("id").Matching(regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)).OnElements("h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowElements("h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowAttrs("start").Matching(bluemonday.Integer).OnElements("ol")
	p.AllowElements("ol")
	p.AllowAttrs("align").Matching(regexp.MustCompile(`^(left|right|center)$`)).OnElements("th", "td")
	p.AllowElements("th", "td")
	p.AllowAttrs("class").Matching(regexp.MustCompile(`^[A-Za-z0-9_ -]{1,64}$`)).OnElements("pre", "code", "span")
	p.AllowElements("pre", "code", "span")
	p.AllowAttrs("href", "title").OnElements("a")
	p.AllowAttrs("src", "alt", "title").OnElements("img")
	p.AllowAttrs("type").Matching(regexp.MustCompile(`^checkbox$`)).OnElements("input")
	p.AllowAttrs("checked", "disabled").Matching(regexp.MustCompile(`^(|checked|disabled)$`)).OnElements("input")
	p.RequireNoFollowOnFullyQualifiedLinks(true)
	p.RequireNoReferrerOnFullyQualifiedLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true) // also adds rel="noopener"
	return p
}()

// Render turns one page's Markdown into sanitized HTML: GFM, heading ids,
// fenced code highlighted with CSS classes (never inline styles), relative
// page links rewritten to console routes and images to the asset route.
// Raw HTML in the source is dropped.
func Render(site Site, slug, markdown string) Rendered {
	src := []byte(markdown)
	md := goldmark.New(
		goldmark.WithExtensions(extension.Strikethrough, extension.Linkify, extension.TaskList,
			extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute))),
		goldmark.WithParserOptions(parser.WithAutoHeadingID(), parser.WithASTTransformers(util.Prioritized(&linkRewriter{site: site, slug: slug}, 100))),
		goldmark.WithRendererOptions(renderer.WithNodeRenderers(util.Prioritized(codeRenderer{}, 100))),
	)
	doc := md.Parser().Parse(text.NewReader(src))
	var out Rendered
	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, src, doc); err != nil {
		buf.Reset() // unreachable with a bytes.Buffer; render nothing rather than half a page
	}
	out.HTML = policy.Sanitize(buf.String())
	var heads []string
	var body strings.Builder
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			if n.Type() == ast.TypeBlock {
				body.WriteByte('\n')
			}
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Heading:
			t := clean(plain(n, src))
			if (n.Level == 2 || n.Level == 3) && t != "" {
				id, _ := n.AttributeString("id")
				ids, _ := id.([]byte)
				out.Outline = append(out.Outline, store.DocHeading{ID: string(ids), Text: t, Level: n.Level})
				heads = append(heads, t)
			}
		case *ast.Text:
			body.Write(textValue(n, src))
			if n.SoftLineBreak() || n.HardLineBreak() {
				body.WriteByte(' ')
			}
		case *ast.String:
			body.Write(n.Value)
		case *ast.AutoLink:
			body.Write(n.Label(src))
		case *ast.FencedCodeBlock, *ast.CodeBlock:
			lines := n.Lines()
			for i := 0; i < lines.Len(); i++ {
				seg := lines.At(i)
				body.Write(seg.Value(src))
			}
		}
		return ast.WalkContinue, nil
	})
	out.Headings = strings.Join(heads, "\n")
	out.Body = clean(body.String())
	return out
}

// plain is the text of an inline subtree.
func plain(n ast.Node, src []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch c := c.(type) {
		case *ast.Text:
			b.Write(textValue(c, src))
		case *ast.String:
			b.Write(c.Value)
		case *ast.AutoLink:
			b.Write(c.Label(src))
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}

// textValue is a text node as displayed: backslash escapes and entities
// resolved (raw text, as in code spans, stays verbatim).
func textValue(n *ast.Text, src []byte) []byte {
	v := n.Value(src)
	if n.IsRaw() {
		return v
	}
	return util.ResolveEntityNames(util.UnescapePunctuations(v))
}

var spaces = regexp.MustCompile(`[ \t]+`)
var blank = regexp.MustCompile(`\n{3,}`)

// privateUse are code points the store uses as markers while indexing and
// highlighting (store.SnippetStart and others); they never reach the index,
// nor do NUL (Postgres text refuses it) and carriage returns.
var privateUse = regexp.MustCompile(`[\x{E000}-\x{E0FF}\r\x00]`)

// clean normalises whitespace and removes the store's marker code points.
func clean(s string) string {
	s = privateUse.ReplaceAllString(s, "")
	s = spaces.ReplaceAllString(s, " ")
	return strings.TrimSpace(blank.ReplaceAllString(s, "\n\n"))
}

// linkRewriter points relative links and images at console routes.
type linkRewriter struct {
	site Site
	slug string
}

func (l *linkRewriter) Transform(doc *ast.Document, _ text.Reader, _ parser.Context) {
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Link:
			n.Destination = []byte(l.site.link(l.slug, string(n.Destination)))
		case *ast.Image:
			n.Destination = []byte(l.site.image(l.slug, string(n.Destination)))
		}
		return ast.WalkContinue, nil
	})
}

// bases are the directories a page's relative links may be relative to. A
// slug does not say whether it came from x.md (links relative to x's parent)
// or x/index.md (relative to x), so both are tried, file form first.
func bases(slug string) []string {
	if slug == "index" {
		return []string{""}
	}
	parent := path.Dir(slug)
	if parent == "." {
		parent = ""
	}
	return []string{parent, slug}
}

// resolve joins a relative reference to a base; false when it leaves the tree.
func resolve(base, rel string) (string, bool) {
	if escapes(base, rel) {
		return "", false
	}
	return strings.TrimPrefix(path.Clean("/"+path.Join(base, rel)), "/"), true
}

// escapes reports whether rel climbs above the docs root from base.
func escapes(base, rel string) bool {
	depth := 0
	if base != "" {
		depth = len(strings.Split(base, "/"))
	}
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return true
			}
		default:
			depth++
		}
	}
	return false
}

// slugOf maps a page file path to its slug.
func slugOf(file string) string {
	s := strings.TrimSuffix(file, ".md")
	if s != "index" {
		s = strings.TrimSuffix(s, "/index")
	}
	return s
}

// link rewrites a link destination. Anchors, absolute URLs (the sanitizer
// keeps only http, https and mailto) and root-relative portal routes stay;
// relative .md links become /help/<module>/<slug>[#anchor], relative image
// links the asset route; anything else unresolvable is emptied.
func (s Site) link(slug, dest string) string {
	if dest == "" || strings.HasPrefix(dest, "#") {
		return dest
	}
	if strings.HasPrefix(dest, "//") {
		return ""
	}
	u, err := url.Parse(dest)
	if err != nil {
		return ""
	}
	if u.Scheme != "" || strings.HasPrefix(dest, "/") {
		return dest
	}
	frag := ""
	if u.Fragment != "" {
		frag = "#" + url.PathEscape(u.Fragment)
	}
	if strings.HasSuffix(u.Path, ".md") {
		first := ""
		for _, b := range bases(slug) {
			p, ok := resolve(b, u.Path)
			if !ok {
				continue
			}
			target := slugOf(p)
			if first == "" {
				first = target
			}
			if s.Pages[target] {
				return PageRoute + s.Module + "/" + target + frag
			}
		}
		if first == "" {
			return ""
		}
		return PageRoute + s.Module + "/" + first + frag
	}
	if a := s.image(slug, u.Path); a != "" {
		return a
	}
	return ""
}

// image rewrites an image source to the asset route (with the content hash
// as a cache key); remote and unknown images are emptied (bundles carry
// their images).
func (s Site) image(slug, dest string) string {
	u, err := url.Parse(dest)
	if err != nil || u.Scheme != "" || strings.HasPrefix(dest, "/") || u.Path == "" {
		return ""
	}
	for _, b := range bases(slug) {
		p, ok := resolve(b, u.Path)
		if !ok {
			continue
		}
		if sum, ok := s.Assets[p]; ok {
			v := sum
			if len(v) > 16 {
				v = v[:16]
			}
			return AssetRoute + s.Module + "/assets/" + p + "?v=" + v
		}
	}
	return ""
}

// codeRenderer highlights fenced code with chroma, emitting CSS classes only
// (the edge CSP has no 'unsafe-inline'; the shell ships the stylesheet).
type codeRenderer struct{}

func (codeRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindFencedCodeBlock, renderFenced)
}

var formatter = chromahtml.New(chromahtml.WithClasses(true))

func renderFenced(w util.BufWriter, src []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkSkipChildren, nil
	}
	n := node.(*ast.FencedCodeBlock)
	var code bytes.Buffer
	lines := n.Lines()
	for i := 0; i < lines.Len(); i++ {
		seg := lines.At(i)
		code.Write(seg.Value(src))
	}
	lang := ""
	if n.Info != nil {
		lang = string(n.Language(src))
	}
	var lexer chroma.Lexer
	if lang != "" {
		lexer = lexers.Get(lang)
	}
	if lexer == nil {
		lexer = lexers.Fallback
	}
	it, err := chroma.Coalesce(lexer).Tokenise(nil, code.String())
	if err == nil {
		var out bytes.Buffer
		if err = formatter.Format(&out, styles.Fallback, it); err == nil {
			_, _ = w.Write(out.Bytes())
			return ast.WalkSkipChildren, nil
		}
	}
	_, _ = w.WriteString("<pre><code>")
	html.DefaultWriter.Write(w, code.Bytes())
	_, _ = w.WriteString("</code></pre>\n")
	return ast.WalkSkipChildren, nil
}

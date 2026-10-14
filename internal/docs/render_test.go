package docs

import (
	"regexp"
	"strings"
	"testing"
)

var site = Site{Module: "ipam",
	Pages:  map[string]bool{"index": true, "getting-started": true, "guides": true, "guides/subnets": true, "reference": true},
	Assets: map[string]string{"images/form.png": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "guides/shot.png": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}

// TestSanitizer: whatever the Markdown carries, the HTML has no script, no
// event handlers, no frames, no style attributes and no dangerous URLs.
func TestSanitizer(t *testing.T) {
	for _, tc := range []struct {
		name, md string
		forbid   []string
	}{
		{"script tag", "hi\n\n<script>alert(1)</script>\n", []string{"<script", "alert(1)"}},
		{"inline script", "a <script>alert(1)</script> b", []string{"<script"}},
		{"javascript link", "[x](javascript:alert(1))", []string{"javascript:"}},
		{"javascript autolink", "<javascript:alert(1)>", []string{"href=\"javascript"}},
		{"onerror", `<img src=x onerror="alert(1)">`, []string{"onerror"}},
		{"onerror in markdown image title", `![a](images/form.png "x\" onerror=\"alert(1)")`, []string{`onerror="`}},
		{"iframe", "<iframe src=\"https://evil.example\"></iframe>", []string{"<iframe"}},
		{"style attribute", `<p style="color:red">x</p>`, []string{"style="}},
		{"style element", "<style>body{display:none}</style>", []string{"<style"}},
		{"data link", "[x](data:text/html;base64,PHNjcmlwdD4=)", []string{"data:"}},
		{"data image", "![x](data:image/png;base64,AAAA)", []string{"data:"}},
		{"vbscript", "[x](vbscript:msgbox)", []string{"vbscript:"}},
		{"protocol relative", "[x](//evil.example/a)", []string{"evil.example"}},
		{"form", "<form action=\"/x\"><input name=a></form>", []string{"<form"}},
		{"remote image", "![x](https://evil.example/t.png)", []string{"evil.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Render(site, "index", tc.md).HTML
			for _, f := range tc.forbid {
				if strings.Contains(strings.ToLower(got), strings.ToLower(f)) {
					t.Fatalf("%q survived:\n%s", f, got)
				}
			}
		})
	}
}

func TestExternalLinks(t *testing.T) {
	got := Render(site, "index", "[a](https://example.org/x) [m](mailto:a@example.org) [r](/ipam/subnets)").HTML
	for _, want := range []string{`href="https://example.org/x"`, `target="_blank"`, `noopener`, `noreferrer`, `href="mailto:a@example.org"`, `href="/ipam/subnets"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Count(got, `target="_blank"`) != 1 {
		t.Fatalf("only the fully qualified http link opens a new tab: %s", got)
	}
}

// TestHighlight: fenced code is highlighted with class attributes only.
func TestHighlight(t *testing.T) {
	got := Render(site, "index", "```go\nfunc main() { fmt.Println(\"<b>\") }\n```\n\n```\nplain <text>\n```\n").HTML
	if !strings.Contains(got, `class="chroma"`) || !strings.Contains(got, `<span class="kd">func</span>`) {
		t.Fatalf("not highlighted: %s", got)
	}
	if strings.Contains(got, "style=") || strings.Contains(got, "<b>") || strings.Contains(got, "<text>") {
		t.Fatalf("inline style or unescaped code: %s", got)
	}
	for _, m := range regexp.MustCompile(`\s([a-z-]+)=`).FindAllStringSubmatch(got, -1) {
		if m[1] != "class" {
			t.Fatalf("attribute %q in highlighted code: %s", m[1], got)
		}
	}
}

func TestLinkRewrite(t *testing.T) {
	for _, tc := range []struct {
		name, slug, md, want string
	}{
		{"sibling page", "getting-started", "[s](reference.md)", `href="/help/ipam/reference"`},
		{"nested page with anchor", "index", "[s](guides/subnets.md#fields)", `href="/help/ipam/guides/subnets#fields"`},
		{"from nested page up", "guides/subnets", "[s](../reference.md)", `href="/help/ipam/reference"`},
		{"index page links relative to its own directory", "guides", "[s](subnets.md)", `href="/help/ipam/guides/subnets"`},
		{"directory index", "getting-started", "[s](guides/index.md)", `href="/help/ipam/guides"`},
		{"root index", "guides/subnets", "[s](../index.md)", `href="/help/ipam/index"`},
		{"in-page anchor", "index", "[s](#top)", `href="#top"`},
		{"portal route", "index", "[s](/ipam/subnets)", `href="/ipam/subnets"`},
		{"image", "index", "![f](images/form.png)", `src="/gateway/v1/docs/ipam/assets/images/form.png?v=0123456789abcdef"`},
		{"image from nested page", "guides/subnets", "![f](../images/form.png)", `src="/gateway/v1/docs/ipam/assets/images/form.png?v=0123456789abcdef"`},
		{"image next to index page", "guides", "![f](shot.png)", `src="/gateway/v1/docs/ipam/assets/guides/shot.png?v=fedcba9876543210"`},
		{"link to an image", "index", "[f](images/form.png)", `href="/gateway/v1/docs/ipam/assets/images/form.png?v=0123456789abcdef"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Render(site, tc.slug, tc.md).HTML; !strings.Contains(got, tc.want) {
				t.Fatalf("want %s in %s", tc.want, got)
			}
		})
	}
	// Escaping the tree or naming unknown files leaves nothing to follow.
	for _, md := range []string{"[s](../../etc/passwd.md)", "![f](../../x.png)", "![f](missing.png)", "[x](notes.txt)"} {
		got := Render(site, "index", md).HTML
		if strings.Contains(got, "passwd") || strings.Contains(got, "x.png") || strings.Contains(got, "missing.png") || strings.Contains(got, "notes.txt") {
			t.Fatalf("%s → %s", md, got)
		}
	}
}

func TestOutlineAndBody(t *testing.T) {
	r := Render(site, "index", "# Title\n\nIntro *text* with `code`.\n\n## First part\n\nBody one.\n\n### Detail \\<x>\n\n```sh\nipam list\n```\n\n#### Deep\n\n## Second\n\n| a | b |\n|---|---|\n| cell | two |\n")
	if len(r.Outline) != 3 || r.Outline[0].ID != "first-part" || r.Outline[0].Text != "First part" || r.Outline[0].Level != 2 ||
		r.Outline[1].Level != 3 || r.Outline[1].Text != "Detail <x>" || r.Outline[2].Text != "Second" {
		t.Fatalf("%+v", r.Outline)
	}
	if !strings.Contains(r.HTML, `<h2 id="first-part">`) {
		t.Fatalf("heading ids: %s", r.HTML)
	}
	if r.Headings != "First part\nDetail <x>\nSecond" {
		t.Fatalf("%q", r.Headings)
	}
	for _, want := range []string{"Intro text with code.", "Body one.", "ipam list", "cell", "Deep"} {
		if !strings.Contains(r.Body, want) {
			t.Fatalf("body misses %q: %q", want, r.Body)
		}
	}
	if b := Render(site, "index", "a \uE000b\uE001 c\x00").Body; strings.ContainsAny(b, "\uE000\uE001\x00") {
		t.Fatal("snippet markers must be stripped from the body")
	}
}

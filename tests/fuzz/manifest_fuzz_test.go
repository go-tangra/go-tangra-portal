package fuzz

import (
	"os"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
	"github.com/go-tangra/go-tangra-portal/v4/internal/route"
)

func FuzzManifest(f *testing.F) {
	valid, _ := os.ReadFile("../../internal/manifest/testdata/valid.json")
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"module":"a"}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := manifest.Parse(raw)
		if err != nil {
			return
		}
		for _, r := range m.Routes {
			if r.Public == (r.Permission != "") {
				t.Fatalf("unprotected route accepted: %+v", r)
			}
		}
		for _, mt := range m.Methods {
			if mt.Public == (mt.Permission != "") {
				t.Fatalf("unprotected method accepted: %+v", mt)
			}
		}
		if _, err := route.Build([]route.Module{{Name: m.Module, State: "active", Manifest: m}}); err != nil {
			t.Fatalf("valid manifest cannot build a table: %v", err)
		}
	})
}

func FuzzCASLRule(f *testing.F) {
	f.Add(`{"a":{"$eq":1}}`)
	f.Add(`{"a":{"$where":"x"}}`)
	f.Add(`{"a":[1,2,{"$in":[1]}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		var c map[string]any
		if err := jsonUnmarshal([]byte(s), &c); err != nil {
			return
		}
		if err := manifest.ValidateConditions(c); err == nil && strings.Contains(s, "$where") {
			t.Fatalf("forbidden operator accepted: %s", s)
		}
	})
}

func FuzzPrefix(f *testing.F) {
	for _, s := range []string{"/api", "/api/", "/a/../b", "", "/{x}", "/a%20b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := manifest.NormalizePrefix(s)
		if ok && (!strings.HasPrefix(n, "/") || strings.HasSuffix(n, "/") || strings.Contains(n, "//") || strings.Contains(n, "/../") || strings.Contains(n, "{")) {
			t.Fatalf("%q normalised to %q", s, n)
		}
	})
}

func FuzzRoutePath(f *testing.F) {
	for _, s := range []string{"/", "/a/b", "/a/../b", "/a%2f..%2fb", "/a//b", "/a%00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := route.Normalize(s)
		if ok && (strings.Contains(n, "/../") || strings.HasSuffix(n, "/..") || strings.Contains(n, "//") || strings.ContainsAny(n, "\x00\\")) {
			t.Fatalf("%q normalised to %q", s, n)
		}
	})
}

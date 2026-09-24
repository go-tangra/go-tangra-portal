package route

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
)

func mod(name string, prefixes []string, routes []manifest.Route, methods []manifest.Method) Module {
	return Module{Name: name, State: "active", Manifest: manifest.Manifest{Module: name, Prefixes: prefixes, Routes: routes, Methods: methods}}
}

func TestBuildAndMatch(t *testing.T) {
	orders := mod("orders", []string{"/api/orders"}, []manifest.Route{
		{Method: "GET", Path: "/api/orders", Permission: "orders:read"},
		{Method: "GET", Path: "/api/orders/{id}", Permission: "orders:read", Timeout: "5s"},
		{Method: "GET", Path: "/api/orders/latest", Public: true},
		{Method: "POST", Path: "/api/orders", Permission: "orders:write", MaxBodyBytes: 100},
	}, []manifest.Method{{FullMethod: "/orders.v1.Orders/Get", Permission: "orders:read"}, {FullMethod: "/orders.v1.Orders/Watch", Permission: "orders:read", Streaming: true, MaxStreamDuration: "1h"}})
	auth := mod("auth", []string{"/api/v1", "/.well-known"}, []manifest.Route{{Method: "GET", Path: "/.well-known/jwks.json", Public: true}}, nil)
	tb, err := Build([]Module{orders, auth})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := tb.Match("GET", "/api/orders/42")
	if !ok || r.Module != "orders" || r.Params["id"] != "42" || r.Permission != "orders:read" || r.Timeout != 5*time.Second {
		t.Fatalf("%+v %v", r, ok)
	}
	// Literal segments win over parameters.
	if r, ok := tb.Match("GET", "/api/orders/latest"); !ok || !r.Public {
		t.Fatalf("%+v", r)
	}
	if r, ok := tb.Match("POST", "/api/orders"); !ok || r.MaxBody != 100 {
		t.Fatalf("%+v", r)
	}
	if _, ok := tb.Match("DELETE", "/api/orders"); ok {
		t.Fatal("undeclared method matched")
	}
	if r, ok := tb.Match("GET", "/api/orders/42/lines"); ok || r.Module != "orders" {
		t.Fatalf("undeclared path must not match but names the owner: %+v %v", r, ok)
	}
	if _, ok := tb.Match("GET", "/api/other"); ok {
		t.Fatal("foreign path matched")
	}
	if r, ok := tb.Match("GET", "/.well-known/jwks.json"); !ok || r.Module != "auth" {
		t.Fatalf("%+v", r)
	}
	if m, ok := tb.MatchMethod("/orders.v1.Orders/Watch"); !ok || !m.Streaming || m.MaxStream != time.Hour {
		t.Fatalf("%+v", m)
	}
	if _, ok := tb.MatchMethod("/orders.v1.Orders/Nope"); ok {
		t.Fatal("unknown method")
	}
	if tb.RemoteState("orders") != "active" || tb.RemoteState("ghost") != "" {
		t.Fatal("remote state")
	}
	// Catch-all tail parameter: matches any depth, loses against literal routes.
	console := mod("auth", []string{"/console"}, []manifest.Route{{Method: "GET", Path: "/console/{path...}", Public: true}, {Method: "GET", Path: "/console/health", Public: true}, {Method: "GET", Path: "/console", Public: true}}, nil)
	tc, err := Build([]Module{console})
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := tc.Match("GET", "/console/admin/users/1"); !ok || r.Params["path"] != "admin/users/1" {
		t.Fatalf("%+v %v", r, ok)
	}
	if r, ok := tc.Match("GET", "/console/health"); !ok || r.Params != nil {
		t.Fatalf("literal must win over catch-all: %+v", r)
	}
	if r, ok := tc.Match("GET", "/console"); !ok || r.Pattern != "/console" {
		t.Fatalf("%+v", r)
	}
	if _, ok := tc.Match("POST", "/console/x"); ok {
		t.Fatal("method")
	}
	// Overlap across modules is refused.
	dup := mod("dup", []string{"/api/orders/reports"}, nil, nil)
	var oe *OverlapError
	if _, err := Build([]Module{orders, dup}); !errors.As(err, &oe) || !strings.Contains(oe.Error(), "/api/orders") {
		t.Fatalf("overlap accepted: %v", err)
	}
	if Empty().root == nil {
		t.Fatal("empty")
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{"/": "/", "/api/orders/": "/api/orders", "/api/%6Frders": "/api/orders", "/a/b": "/a/b"} {
		if got, ok := Normalize(in); !ok || got != want {
			t.Errorf("%q → %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "api", "/a//b", "/a/../b", "/a/./b", "/a%2F..%2Fb", "/a\\b", "/a%00b", "/a%zz", "/" + string(make([]byte, 3000))} {
		if _, ok := Normalize(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestConcurrentLookups(t *testing.T) {
	tb, _ := Build([]Module{mod("a", []string{"/a"}, []manifest.Route{{Method: "GET", Path: "/a/{x}", Public: true}}, nil)})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, ok := tb.Match("GET", "/a/x"); !ok {
					t.Error("lost match")
					return
				}
			}
		}()
	}
	wg.Wait()
}

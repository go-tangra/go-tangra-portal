package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
)

func load(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutate(t *testing.T, raw []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	f(m)
	out, _ := json.Marshal(m)
	return out
}

func TestParseValid(t *testing.T) {
	m, err := Parse(load(t))
	if err != nil {
		t.Fatal(err)
	}
	if m.Module != "orders" || len(m.Routes) != 4 || len(m.Methods) != 3 || len(m.Abilities) != 2 || m.Prefixes[0] != "/api/orders" {
		t.Fatalf("%+v", m)
	}
	if s := m.Subjects(); len(s) != 1 || s[0] != "Order" {
		t.Fatal(s)
	}
	ok := mutate(t, load(t), func(m map[string]any) {
		m["routes"] = []any{map[string]any{"method": "GET", "path": "/api/orders/files/{rest...}", "permission": "orders:read"}}
	})
	if _, err := Parse(ok); err != nil {
		t.Fatalf("catch-all route refused: %v", err)
	}
}

func TestParseRefusals(t *testing.T) {
	raw := load(t)
	cases := map[string]func(m map[string]any){
		"bad module name": func(m map[string]any) { m["module"] = "Orders!" },
		"unknown field":   func(m map[string]any) { m["extra"] = 1 },
		"prefix overlap":  func(m map[string]any) { m["prefixes"] = []any{"/api", "/api/orders"} },
		"relative prefix": func(m map[string]any) { m["prefixes"] = []any{"api/orders"} },
		"dot prefix":      func(m map[string]any) { m["prefixes"] = []any{"/api/../x"} },
		"route outside prefix": func(m map[string]any) {
			m["routes"] = []any{map[string]any{"method": "GET", "path": "/elsewhere", "permission": "orders:read"}}
		},
		"route unprotected": func(m map[string]any) { m["routes"] = []any{map[string]any{"method": "GET", "path": "/api/orders"}} },
		"route public+perm": func(m map[string]any) {
			m["routes"] = []any{map[string]any{"method": "GET", "path": "/api/orders", "public": true, "permission": "orders:read"}}
		},
		"route undeclared perm": func(m map[string]any) {
			m["routes"] = []any{map[string]any{"method": "GET", "path": "/api/orders", "permission": "orders:nope"}}
		},
		"route bad param": func(m map[string]any) {
			m["routes"] = []any{map[string]any{"method": "GET", "path": "/api/orders/{Id}", "permission": "orders:read"}}
		},
		"route long timeout": func(m map[string]any) {
			m["routes"] = []any{map[string]any{"method": "GET", "path": "/api/orders", "permission": "orders:read", "timeout": "10m"}}
		},
		"duplicate route": func(m map[string]any) {
			m["routes"] = []any{map[string]any{"method": "GET", "path": "/api/orders", "permission": "orders:read"}, map[string]any{"method": "GET", "path": "/api/orders", "permission": "orders:read"}}
		},
		"method unprotected": func(m map[string]any) { m["methods"] = []any{map[string]any{"full_method": "/a.b.C/D"}} },
		"method bad name":    func(m map[string]any) { m["methods"] = []any{map[string]any{"full_method": "a.b.C/D", "public": true}} },
		"ability undeclared": func(m map[string]any) {
			m["abilities"] = []any{map[string]any{"action": []any{"read"}, "subject": []any{"Order"}, "requires": "x:y"}}
		},
		"ability bad operator": func(m map[string]any) {
			m["abilities"] = []any{map[string]any{"action": []any{"read"}, "subject": []any{"Order"}, "conditions": map[string]any{"a": map[string]any{"$where": "1"}}, "requires": "orders:read"}}
		},
		"ability huge condition": func(m map[string]any) {
			m["abilities"] = []any{map[string]any{"action": []any{"read"}, "subject": []any{"Order"}, "conditions": map[string]any{"a": strings.Repeat("x", 5000)}, "requires": "orders:read"}}
		},
		"nav undeclared": func(m map[string]any) {
			m["nav"] = []any{map[string]any{"title": "x", "path": "/x", "order": 1, "requires": "a:b"}}
		},
		"remote wrong entry": func(m map[string]any) {
			m["remote"] = map[string]any{"entry": "/m/other/mf-manifest.json", "exposes": []any{"./routes"}}
		},
		"remote bad expose": func(m map[string]any) {
			m["remote"] = map[string]any{"entry": "/m/orders/mf-manifest.json", "exposes": []any{"./evil"}}
		},
		"duplicate perm": func(m map[string]any) {
			m["permissions"] = []any{map[string]any{"resource": "orders", "action": "read"}, map[string]any{"resource": "orders", "action": "read"}}
		},
	}
	for name, f := range cases {
		if _, err := Parse(mutate(t, raw, f)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if _, err := Parse([]byte("{")); !errors.Is(err, ErrInvalid) {
		t.Fatal("malformed json")
	}
	if _, err := Parse([]byte(strings.Repeat(" ", MaxManifestBytes+1))); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized")
	}
}

func TestNormalizeAndOverlap(t *testing.T) {
	for in, want := range map[string]string{"/api/orders/": "/api/orders", "/a": "/a"} {
		if got, ok := NormalizePrefix(in); !ok || got != want {
			t.Errorf("%q → %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "/", "api", "/a//b", "/a/./b", "/a/{id}", "/a%2Fb", "/a b", "/" + strings.Repeat("x", 200)} {
		if _, ok := NormalizePrefix(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if !Overlaps("/api", "/api/x") || !Overlaps("/api/x", "/api") || Overlaps("/api", "/apix") || !Overlaps("/a", "/a") {
		t.Fatal("overlap")
	}
}

func TestFromProto(t *testing.T) {
	cond, _ := structpb.NewStruct(map[string]any{"ownerId": map[string]any{"$eq": "me"}})
	p := &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders/"},
		Routes:      []*gatewayv1.Route{{Method: "GET", Path: "/api/orders", Permission: "orders:read"}},
		Methods:     []*gatewayv1.Method{{FullMethod: "/orders.v1.Orders/Get", Permission: "orders:read"}},
		Permissions: []*gatewayv1.Permission{{Resource: "orders", Action: "read"}},
		Abilities:   []*gatewayv1.Ability{{Action: []string{"read"}, Subject: []string{"Order"}, Conditions: cond, Requires: "orders:read"}},
		Remote:      &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}},
		Nav:         []*gatewayv1.NavEntry{{Title: "Orders", Path: "/orders", Order: 1, Requires: "orders:read"}}}
	m, err := FromProto(p)
	if err != nil || m.Prefixes[0] != "/api/orders" || m.Abilities[0].Conditions["ownerId"] == nil {
		t.Fatalf("%+v %v", m, err)
	}
	p.Routes[0].Permission = ""
	if _, err := FromProto(p); !errors.Is(err, ErrInvalid) {
		t.Fatal("unprotected route accepted via proto")
	}
	if _, err := FromProto(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil")
	}
	for d, want := range map[time.Duration]string{0: "", time.Hour: "60m", 90 * time.Second: "90s", 1500 * time.Millisecond: "1500ms", 5 * time.Second: "5s"} {
		if got := dur(d); got != want {
			t.Errorf("dur(%s) = %q want %q", d, got, want)
		}
	}
	p.Routes[0].Permission = "orders:read"
	p.Methods[0].MaxStreamDuration = durationpb.New(time.Hour)
	p.Methods[0].Streaming = true
	if _, err := FromProto(p); err != nil {
		t.Fatalf("hour-long stream cap refused: %v", err)
	}
}

// Direct validation paths the schema would otherwise catch first.
func TestValidateDirect(t *testing.T) {
	base := func() Manifest {
		m, _ := Parse(load(t))
		return m
	}
	cases := map[string]func(m *Manifest){
		"bad permission ref":     func(m *Manifest) { m.Permissions = append(m.Permissions, Permission{Resource: "Bad!", Action: "x"}) },
		"bad route timeout":      func(m *Manifest) { m.Routes[0].Timeout = "soon" },
		"negative route timeout": func(m *Manifest) { m.Routes[0].Timeout = "-5s" },
		"bad stream duration":    func(m *Manifest) { m.Methods[1].MaxStreamDuration = "later" },
		"huge stream duration":   func(m *Manifest) { m.Methods[1].MaxStreamDuration = "48h" },
		"duplicate method":       func(m *Manifest) { m.Methods = append(m.Methods, m.Methods[0]) },
		"method undeclared perm": func(m *Manifest) { m.Methods[0].Permission = "x:y" },
		"bad prefix":             func(m *Manifest) { m.Prefixes = []string{"relative"} },
		"route unprotected":      func(m *Manifest) { m.Routes[0].Permission = "" },
		"route bad param":        func(m *Manifest) { m.Routes[1].Path = "/api/orders/{Id}" },
		"catch-all not last":     func(m *Manifest) { m.Routes[1].Path = "/api/orders/{rest...}/x" },
		"method unprotected":     func(m *Manifest) { m.Methods[0].Permission = "" },
	}
	for name, mut := range cases {
		m := base()
		mut(&m)
		if err := m.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Condition grammar edge cases through the walker.
	for name, c := range map[string]map[string]any{
		"empty key":      {"": 1},
		"long key":       {strings.Repeat("k", 70): 1},
		"key with space": {"a b": 1},
		"nested deep":    {"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": map[string]any{"f": map[string]any{"g": map[string]any{"h": 1}}}}}}}},
		"long list":      {"a": map[string]any{"$in": make([]any, 101)}},
		"bad value":      {"a": []any{make(chan int)}},
		"bad nested":     {"a": []any{map[string]any{"$where": 1}}},
	} {
		if err := ValidateConditions(c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ValidateConditions(map[string]any{"a": []any{"x", 1.5, true, nil, map[string]any{"$gt": 1}}}); err != nil {
		t.Fatal(err)
	}
	if got := schemaReason(errors.New("top\n  - deeper\n    - deepest")); got != "deepest" {
		t.Fatalf("%q", got)
	}
	// FromProto without a remote fails validation (entry required), never panics.
	if _, err := FromProto(&gatewayv1.Manifest{Module: "orders"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil remote")
	}
}

func TestSchemaCompile(t *testing.T) {
	if _, err := compile([]byte("{")); err == nil {
		t.Fatal("malformed schema compiled")
	}
	if _, err := compile([]byte(`{"type": 5}`)); err == nil {
		t.Fatal("invalid schema compiled")
	}
	if s, err := compile([]byte(`{"type": "object"}`)); err != nil || s == nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("mustCompile must panic on a broken schema")
		}
	}()
	mustCompile([]byte("{"))
}

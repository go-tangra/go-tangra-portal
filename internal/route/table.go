package route

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-freya/freya/services/gateway/internal/manifest"
)

// Module is what the table needs from a registration.
type Module struct {
	Name     string
	State    string // active | draining | unhealthy
	Manifest manifest.Manifest
}

// Route is the resolved protection of a matched HTTP route.
type Route struct {
	Module     string
	Method     string
	Pattern    string
	Permission string
	Public     bool
	MaxBody    int64
	Timeout    time.Duration
	// ClientAddress: forward the client IP to the module for this route.
	ClientAddress bool
	State         string
	Params        map[string]string
}

// Method is the resolved protection of a gRPC method.
type Method struct {
	Module     string
	FullMethod string
	Permission string
	Public     bool
	Streaming  bool
	MaxStream  time.Duration
	State      string
}

type node struct {
	children map[string]*node
	module   *moduleRoutes
}

type moduleRoutes struct {
	name   string
	state  string
	prefix string
	byMeth map[string][]pattern
}

type pattern struct {
	segments []string
	route    manifest.Route
}

// Table is an immutable snapshot; build a new one on every registry change.
type Table struct {
	root    *node
	methods map[string]Method
	modules map[string]*moduleRoutes
	remotes map[string]string // module → state (for /m/<module>)
}

// Build compiles modules into a table. Prefix overlap across modules is an
// error (the registry refuses it earlier; this is defence in depth).
func Build(mods []Module) (*Table, error) {
	t := &Table{root: &node{children: map[string]*node{}}, methods: map[string]Method{}, modules: map[string]*moduleRoutes{}, remotes: map[string]string{}}
	seen := map[string]string{}
	for _, m := range mods {
		t.remotes[m.Name] = m.State
		for _, p := range m.Manifest.Prefixes {
			for other, owner := range seen {
				if manifest.Overlaps(p, other) && owner != m.Name {
					return nil, &OverlapError{Prefix: p, Other: other, Owner: owner}
				}
			}
			seen[p] = m.Name
			mr := &moduleRoutes{name: m.Name, state: m.State, prefix: p, byMeth: map[string][]pattern{}}
			for _, r := range m.Manifest.Routes {
				if r.Path == p || strings.HasPrefix(r.Path, p+"/") {
					mr.byMeth[r.Method] = append(mr.byMeth[r.Method], pattern{segments: split(r.Path), route: r})
				}
			}
			for meth := range mr.byMeth {
				ps := mr.byMeth[meth]
				sort.SliceStable(ps, func(i, j int) bool { return literalScore(ps[i].segments) > literalScore(ps[j].segments) })
			}
			n := t.root
			for _, seg := range split(p) {
				c, ok := n.children[seg]
				if !ok {
					c = &node{children: map[string]*node{}}
					n.children[seg] = c
				}
				n = c
			}
			n.module = mr
			t.modules[m.Name+p] = mr
		}
		for _, mt := range m.Manifest.Methods {
			dur, _ := time.ParseDuration(mt.MaxStreamDuration)
			t.methods[mt.FullMethod] = Method{Module: m.Name, FullMethod: mt.FullMethod, Permission: mt.Permission, Public: mt.Public, Streaming: mt.Streaming, MaxStream: dur, State: m.State}
		}
	}
	return t, nil
}

// OverlapError reports a prefix owned by two modules.
type OverlapError struct{ Prefix, Other, Owner string }

func (e *OverlapError) Error() string {
	return "route: prefix " + e.Prefix + " overlaps " + e.Other + " owned by " + e.Owner
}

// literalScore orders patterns: more literal segments first, catch-alls last.
func literalScore(segs []string) int {
	n := 0
	for _, s := range segs {
		if !strings.HasPrefix(s, "{") {
			n += 2
		} else if !strings.HasSuffix(s, "...}") {
			n++
		}
	}
	if len(segs) > 0 && strings.HasSuffix(segs[len(segs)-1], "...}") {
		n -= 100
	}
	return n
}

func split(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// Normalize canonicalises a request path: percent-decodes once, refuses
// traversal, empty and control segments, trims a trailing slash. ok=false
// means the path must be refused as not_found.
func Normalize(raw string) (string, bool) {
	if raw == "" || raw[0] != '/' || len(raw) > 2048 {
		return "", false
	}
	dec, err := url.PathUnescape(raw)
	if err != nil {
		return "", false
	}
	for _, c := range dec {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "", false
		}
	}
	if strings.Contains(dec, "//") {
		return "", false
	}
	segs := split(dec)
	for _, s := range segs {
		if s == "." || s == ".." {
			return "", false
		}
	}
	if len(segs) == 0 {
		return "/", true
	}
	return "/" + strings.Join(segs, "/"), true
}

// Match resolves an HTTP request; ok=false means no module owns the path.
func (t *Table) Match(method, path string) (Route, bool) {
	segs := split(path)
	n := t.root
	var best *moduleRoutes
	for _, s := range segs {
		c, ok := n.children[s]
		if !ok {
			break
		}
		n = c
		if n.module != nil {
			best = n.module
		}
	}
	if best == nil {
		return Route{}, false
	}
	for _, p := range best.byMeth[method] {
		if params, ok := matchSegments(p.segments, segs); ok {
			r := p.route
			dur, _ := time.ParseDuration(r.Timeout)
			return Route{Module: best.name, Method: r.Method, Pattern: r.Path, Permission: r.Permission, Public: r.Public, MaxBody: r.MaxBodyBytes, Timeout: dur, ClientAddress: r.ClientAddress, State: best.state, Params: params}, true
		}
	}
	// Owned prefix but no declared route: still the module's territory (405/404 decided by the module),
	// but never forwarded without a declared protection — report as unmatched.
	return Route{Module: best.name, State: best.state}, false
}

func matchSegments(pat, segs []string) (map[string]string, bool) {
	catchAll := len(pat) > 0 && strings.HasSuffix(pat[len(pat)-1], "...}")
	if (!catchAll && len(pat) != len(segs)) || (catchAll && len(segs) < len(pat)) {
		return nil, false
	}
	var params map[string]string
	for i, p := range pat {
		if catchAll && i == len(pat)-1 {
			if params == nil {
				params = map[string]string{}
			}
			params[strings.TrimSuffix(strings.Trim(p, "{}"), "...")] = strings.Join(segs[i:], "/")
			return params, true
		}
		if strings.HasPrefix(p, "{") {
			if params == nil {
				params = map[string]string{}
			}
			params[strings.Trim(p, "{}")] = segs[i]
			continue
		}
		if p != segs[i] {
			return nil, false
		}
	}
	return params, true
}

// MatchMethod resolves a gRPC full method.
func (t *Table) MatchMethod(full string) (Method, bool) {
	m, ok := t.methods[full]
	return m, ok
}

// RemoteState returns the state of a module serving /m/<module> ("" = unknown).
func (t *Table) RemoteState(module string) string { return t.remotes[module] }

// Empty is a table with no modules.
func Empty() *Table { t, _ := Build(nil); return t }

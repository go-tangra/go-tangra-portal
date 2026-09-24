package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/go-tangra/go-tangra-portal/sdk/v4/api/schema"
)

// Manifest is a validated module manifest (contracts/manifest.schema.json).
type Manifest struct {
	Module      string       `json:"module"`
	DisplayName string       `json:"display_name"`
	Version     string       `json:"version"`
	Prefixes    []string     `json:"prefixes"`
	Routes      []Route      `json:"routes"`
	Methods     []Method     `json:"methods"`
	Permissions []Permission `json:"permissions"`
	Abilities   []Ability    `json:"abilities"`
	Remote      Remote       `json:"remote"`
	Nav         []NavEntry   `json:"nav"`
}

// Route is an HTTP route with its protection.
type Route struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Permission   string `json:"permission,omitempty"`
	Public       bool   `json:"public,omitempty"`
	MaxBodyBytes int64  `json:"max_body_bytes,omitempty"`
	Timeout      string `json:"timeout,omitempty"`
	// ClientAddress asks the gateway to forward the client IP as
	// X-Gateway-Client-Addr (share-link policies); off by default.
	ClientAddress bool `json:"client_address,omitempty"`
}

// Method is a gRPC method with its protection.
type Method struct {
	FullMethod        string `json:"full_method"`
	Permission        string `json:"permission,omitempty"`
	Public            bool   `json:"public,omitempty"`
	Streaming         bool   `json:"streaming,omitempty"`
	MaxStreamDuration string `json:"max_stream_duration,omitempty"`
}

// Permission is an API permission the module registers in the auth module.
type Permission struct {
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

// Ability is a CASL raw rule bound to an API permission.
type Ability struct {
	Action     []string       `json:"action"`
	Subject    []string       `json:"subject"`
	Fields     []string       `json:"fields,omitempty"`
	Conditions map[string]any `json:"conditions,omitempty"`
	Inverted   bool           `json:"inverted,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Requires   string         `json:"requires"`
}

// Remote locates the Module Federation remote.
type Remote struct {
	Entry     string   `json:"entry"`
	Exposes   []string `json:"exposes"`
	Integrity string   `json:"integrity,omitempty"`
}

// NavEntry is a navigation contribution.
type NavEntry struct {
	Title    string `json:"title"`
	Path     string `json:"path"`
	Icon     string `json:"icon,omitempty"`
	Order    int    `json:"order"`
	Requires string `json:"requires"`
}

// Limits.
const (
	MaxManifestBytes  = 256 << 10
	MaxConditionBytes = 4096
	MaxDurationRoute  = 5 * time.Minute
)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("manifest: invalid")

var compiled = mustCompile(schema.Manifest)

// mustCompile compiles the embedded schema; a broken schema is a build defect.
func mustCompile(raw []byte) *jsonschema.Schema {
	s, err := compile(raw)
	if err != nil {
		panic(err)
	}
	return s
}

// compile loads a JSON Schema document.
func compile(raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	var s *jsonschema.Schema
	if err = c.AddResource("manifest.schema.json", doc); err == nil {
		s, err = c.Compile("manifest.schema.json")
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

var (
	permRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$`)
	paramRE  = regexp.MustCompile(`^\{[a-z][a-z0-9_]*(\.\.\.)?\}$`)
	allowOps = map[string]bool{"$eq": true, "$ne": true, "$in": true, "$nin": true, "$lt": true, "$lte": true, "$gt": true, "$gte": true, "$exists": true}
)

// Parse validates raw JSON against the schema and the semantic rules.
func Parse(raw []byte) (Manifest, error) {
	if len(raw) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: manifest larger than %d bytes", ErrInvalid, MaxManifestBytes)
	}
	doc, err := decodeDoc(raw)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := compiled.Validate(doc); err != nil {
		return Manifest{}, fmt.Errorf("%w: schema: %s", ErrInvalid, schemaReason(err))
	}
	var m Manifest
	// The schema already refused unknown fields and wrong types; decoding
	// cannot fail on a validated document.
	_ = json.Unmarshal(raw, &m)
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func decodeDoc(raw []byte) (any, error) { return jsonschema.UnmarshalJSON(bytes.NewReader(raw)) }

// schemaReason returns the deepest, most specific validation message (one line).
func schemaReason(err error) string {
	lines := strings.Split(err.Error(), "\n")
	return strings.TrimSpace(strings.TrimLeft(lines[len(lines)-1], " -"))
}

// Validate applies the semantic rules the schema cannot express.
func (m *Manifest) Validate() error {
	for i, p := range m.Prefixes {
		n, ok := NormalizePrefix(p)
		if !ok {
			return fmt.Errorf("%w: prefix %q", ErrInvalid, p)
		}
		m.Prefixes[i] = n
	}
	sort.Strings(m.Prefixes)
	for i := 0; i < len(m.Prefixes); i++ {
		for j := i + 1; j < len(m.Prefixes); j++ {
			if Overlaps(m.Prefixes[i], m.Prefixes[j]) {
				return fmt.Errorf("%w: prefixes %q and %q overlap", ErrInvalid, m.Prefixes[i], m.Prefixes[j])
			}
		}
	}
	perms := map[string]bool{}
	for _, p := range m.Permissions {
		ref := p.Resource + ":" + p.Action
		if !permRE.MatchString(ref) || perms[ref] {
			return fmt.Errorf("%w: permission %q", ErrInvalid, ref)
		}
		perms[ref] = true
	}
	seenRoute := map[string]bool{}
	for _, r := range m.Routes {
		if r.Public == (r.Permission != "") {
			return fmt.Errorf("%w: route %s %s must be public or carry a permission", ErrInvalid, r.Method, r.Path)
		}
		if r.Permission != "" && !perms[r.Permission] {
			return fmt.Errorf("%w: route %s %s requires undeclared permission %q", ErrInvalid, r.Method, r.Path, r.Permission)
		}
		if !m.underPrefix(r.Path) {
			return fmt.Errorf("%w: route %s %s outside the owned prefixes", ErrInvalid, r.Method, r.Path)
		}
		segs := strings.Split(strings.TrimPrefix(r.Path, "/"), "/")
		for i, seg := range segs {
			if strings.HasPrefix(seg, "{") && !paramRE.MatchString(seg) {
				return fmt.Errorf("%w: route path parameter %q", ErrInvalid, seg)
			}
			if strings.HasSuffix(seg, "...}") && i != len(segs)-1 {
				return fmt.Errorf("%w: catch-all parameter %q must be last", ErrInvalid, seg)
			}
		}
		if r.Timeout != "" {
			d, err := time.ParseDuration(r.Timeout)
			if err != nil || d <= 0 || d > MaxDurationRoute {
				return fmt.Errorf("%w: route timeout %q", ErrInvalid, r.Timeout)
			}
		}
		key := r.Method + " " + r.Path
		if seenRoute[key] {
			return fmt.Errorf("%w: duplicate route %s", ErrInvalid, key)
		}
		seenRoute[key] = true
	}
	seenMethod := map[string]bool{}
	for _, mt := range m.Methods {
		if mt.Public == (mt.Permission != "") {
			return fmt.Errorf("%w: method %s must be public or carry a permission", ErrInvalid, mt.FullMethod)
		}
		if mt.Permission != "" && !perms[mt.Permission] {
			return fmt.Errorf("%w: method %s requires undeclared permission %q", ErrInvalid, mt.FullMethod, mt.Permission)
		}
		if mt.MaxStreamDuration != "" {
			if d, err := time.ParseDuration(mt.MaxStreamDuration); err != nil || d <= 0 || d > 24*time.Hour {
				return fmt.Errorf("%w: max_stream_duration %q", ErrInvalid, mt.MaxStreamDuration)
			}
		}
		if seenMethod[mt.FullMethod] {
			return fmt.Errorf("%w: duplicate method %s", ErrInvalid, mt.FullMethod)
		}
		seenMethod[mt.FullMethod] = true
	}
	for _, a := range m.Abilities {
		if !perms[a.Requires] {
			return fmt.Errorf("%w: ability requires undeclared permission %q", ErrInvalid, a.Requires)
		}
		if err := ValidateConditions(a.Conditions); err != nil {
			return err
		}
	}
	for _, n := range m.Nav {
		if !perms[n.Requires] {
			return fmt.Errorf("%w: nav entry %q requires undeclared permission %q", ErrInvalid, n.Title, n.Requires)
		}
	}
	if want := "/m/" + m.Module + "/mf-manifest.json"; m.Remote.Entry != want {
		return fmt.Errorf("%w: remote entry must be %s", ErrInvalid, want)
	}
	return nil
}

func (m *Manifest) underPrefix(path string) bool {
	for _, p := range m.Prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// Subjects lists the CASL subjects the manifest claims (collision check at registration).
func (m *Manifest) Subjects() []string {
	set := map[string]bool{}
	for _, a := range m.Abilities {
		for _, s := range a.Subject {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// NormalizePrefix canonicalises an owned prefix: absolute, no trailing slash,
// no empty/dot segments, no parameters, no percent-encoding.
func NormalizePrefix(p string) (string, bool) {
	if p == "" || p[0] != '/' || len(p) > 128 || strings.ContainsAny(p, "%?#\\ \t\r\n") {
		return "", false
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, "{") {
			return "", false
		}
	}
	return p, true
}

// Overlaps reports whether one prefix contains the other.
func Overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// ValidateConditions bounds CASL conditions to a documented MongoDB-style subset.
func ValidateConditions(c map[string]any) error {
	if len(c) == 0 {
		return nil
	}
	// Conditions come from JSON or protobuf structs: always marshalable.
	b, _ := json.Marshal(c)
	if len(b) > MaxConditionBytes {
		return fmt.Errorf("%w: conditions larger than %d bytes", ErrInvalid, MaxConditionBytes)
	}
	return walkConditions(c, 0)
}

func walkConditions(v any, depth int) error {
	if depth > 6 {
		return fmt.Errorf("%w: conditions nested too deeply", ErrInvalid)
	}
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if strings.HasPrefix(k, "$") && !allowOps[k] {
				return fmt.Errorf("%w: condition operator %q not allowed", ErrInvalid, k)
			}
			if !strings.HasPrefix(k, "$") && (k == "" || len(k) > 64 || strings.ContainsAny(k, " \t\r\n")) {
				return fmt.Errorf("%w: condition field %q", ErrInvalid, k)
			}
			if err := walkConditions(val, depth+1); err != nil {
				return err
			}
		}
	case []any:
		if len(x) > 100 {
			return fmt.Errorf("%w: condition list too long", ErrInvalid)
		}
		for _, e := range x {
			if err := walkConditions(e, depth+1); err != nil {
				return err
			}
		}
	case string, float64, int, int64, bool, nil:
	default:
		return fmt.Errorf("%w: unsupported condition value", ErrInvalid)
	}
	return nil
}

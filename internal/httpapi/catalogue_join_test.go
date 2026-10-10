package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

const joinJTI = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

var joinCore = map[string]string{
	"TRUST_DOMAIN": "example.org", "GATEWAY_ISSUER": "https://portal.example.org:8443",
	"LCM_ENROLL_URL": "https://portal.example.org:8443/api/lcm/v1/enroll", "AUTH_GRPC": "portal.example.org:9543",
	"GATEWAY_GRPC": "portal.example.org:9643", "LCM_GRPC": "portal.example.org:9945", "MESH_TENANT_ID": "00000000-0000-0000-0000-000000000001",
}

func joinToken() string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"EdDSA","kid":"k"}`) + "." + enc(`{"jti":"`+joinJTI+`","aud":"lcm"}`) + ".sig"
}

type joinEnv struct {
	s    *Server
	ms   *memstore.Store
	aw   *audit.Writer
	reg  *registry.Registry
	auth *fakeEnroll
}

func newJoinEnv(t *testing.T, configured bool) *joinEnv {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	ms.Owners = []string{"go-tangra"}
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms, Audit: aw})
	bundle, err := fwcat.PackBundle(fstest.MapFS{
		"compose.yaml": {Data: []byte("services: {}\n"), Mode: 0o644},
		"config.yaml":  {Data: []byte("issuer: ${GATEWAY_ISSUER}\nhost: ${MODULE_ADVERTISE_HOST}\n"), Mode: 0o644},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := fwcat.Descriptor{Schema: 1, Module: "sms-gw", DisplayName: "SMS Gateway", Image: "ghcr.io/go-tangra/go-tangra-sms-gw",
		Routes: fwcat.Routes{Prefixes: []string{"/api/sms-gw", "/m/sms-gw"}, Names: []string{"sms-gw"}},
		Bundle: fwcat.BundleSpec{Dir: "deploy/bundle", Templates: []string{"config.yaml"}}, MinCore: map[string]string{"gateway": "9.0.0"},
		HostInputs: []fwcat.HostInput{{Key: "MODULE_ADVERTISE_HOST", Label: "host", Pattern: `^[a-z0-9.-]+$`}}}
	e, err := fwcat.BuildEntry(d, "4.3.0", "go-tangra/go-tangra-sms-gw", []string{"messages:send"}, bundle)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := e.Marshal()
	_ = ms.InsertEntry(ctx, store.CatalogueEntry{Module: "sms-gw", Version: "4.3.0", Repo: "go-tangra/go-tangra-sms-gw", VersionKey: 4_000_003_000_000, Entry: raw, Bundle: bundle})
	auth := &fakeEnroll{token: joinToken(), consumed: map[string]time.Time{}}
	var join *JoinDeps
	if configured {
		join = &JoinDeps{Core: joinCore, MeshCA: func(context.Context) ([]byte, error) {
			return []byte("-----BEGIN CERTIFICATE-----\nmesh\n-----END CERTIFICATE-----\n"), nil
		}, Store: ms}
	}
	s := newTestServer(t)
	s.RegisterOps(OpsDeps{Reg: reg, Ops: &registry.Ops{Reg: reg, Marks: ms, Allow: ms, Audit: aw}, Identity: opsIdentity{}, Audit: ms, Roles: []string{"operator"},
		AdminRoles: []string{"owner", "admin"}, Known: ms, Events: aw, Sources: ms, Refresher: &stubRefresher{}, Enroll: auth, TrustDomain: "example.org", Join: join})
	return &joinEnv{s: s, ms: ms, aw: aw, reg: reg, auth: auth}
}

func zipFiles(t *testing.T, b []byte) map[string]string {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	out := map[string]string{}
	for _, f := range r.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		_ = rc.Close()
		out[f.Name] = string(data)
	}
	return out
}

func TestJoinBundle(t *testing.T) {
	e := newJoinEnv(t, true)
	w := do(e.s, "POST", "/gateway/v1/ops/catalogue/sms-gw/join", `{"inputs":{"MODULE_ADVERTISE_HOST":"sms.example.org"}}`, adminHdr("operator"))
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Join-Id") == "" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body.String()[:min(200, w.Body.Len())])
	}
	if !strings.Contains(w.Header().Get("Content-Disposition"), `sms-gw-join.zip`) {
		t.Fatal(w.Header().Get("Content-Disposition"))
	}
	files := zipFiles(t, w.Body.Bytes())
	if files["sms-gw/config.yaml"] != "issuer: https://portal.example.org:8443\nhost: sms.example.org\n" {
		t.Fatalf("%q", files["sms-gw/config.yaml"])
	}
	if !strings.Contains(files["sms-gw/.env"], `GATEWAY_ISSUER="https://portal.example.org:8443"`) || files["sms-gw/private/enrollment.token"] != joinToken() {
		t.Fatal("core value or token missing")
	}
	// Exactly the module's SPIFFE id, the mesh tenant, 24 h by default.
	if len(e.auth.got) != 1 || strings.Join(e.auth.got[0].GetSpiffePaths(), ",") != "spiffe://example.org/svc/sms-gw" ||
		e.auth.got[0].GetTtlSeconds() != 86400 || e.auth.got[0].GetTenantId() != joinCore["MESH_TENANT_ID"] {
		t.Fatalf("%+v", e.auth.got)
	}
	// The allow-list entry is created with the entry's scope.
	allow, _ := e.ms.ListAllow(context.Background())
	if len(allow) != 1 || allow[0].SpiffeID != "spiffe://example.org/svc/sms-gw" || strings.Join(allow[0].Prefixes, ",") != "/api/sms-gw,/m/sms-gw" || allow[0].Names[0] != "sms-gw" {
		t.Fatalf("%+v", allow)
	}
	// A second bundle keeps the identical entry; the record exists.
	if w := do(e.s, "POST", "/gateway/v1/ops/catalogue/sms-gw/join", `{"inputs":{"MODULE_ADVERTISE_HOST":"sms.example.org"},"ttl_hours":2}`, adminHdr("operator")); w.Code != 200 || e.auth.got[1].GetTtlSeconds() != 7200 {
		t.Fatalf("%d", w.Code)
	}
	if allow, _ := e.ms.ListAllow(context.Background()); len(allow) != 1 {
		t.Fatalf("allow-list duplicated: %d", len(allow))
	}
	if len(e.ms.Joins) != 2 {
		t.Fatalf("join records %d", len(e.ms.Joins))
	}
	e.aw.Close()
	var joins int
	for _, r := range e.ms.Audit() {
		if strings.Contains(string(r.Details), joinToken()) || strings.Contains(string(r.Details), "GEN_PASSWORD") {
			t.Fatal("secret in audit")
		}
		if r.EventType == string(audit.ModuleJoinBundle) {
			joins++
			if r.Module != "sms-gw" || r.ActorID != "op1" || !strings.Contains(string(r.Details), joinJTI) {
				t.Fatalf("%+v %s", r, r.Details)
			}
		}
	}
	if joins != 2 {
		t.Fatalf("join audits %d", joins)
	}
}

func TestJoinRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		who, module, body string
		prep              func(e *joinEnv)
		configured        bool
		want              int
		minted            bool
	}{
		"operator":       {"operator-only", "sms-gw", `{"inputs":{"MODULE_ADVERTISE_HOST":"a.b"}}`, nil, true, 403, false},
		"no entry":       {"operator", "billing", `{"inputs":{}}`, nil, true, 404, false},
		"missing input":  {"operator", "sms-gw", `{"inputs":{}}`, nil, true, 400, false},
		"bad input":      {"operator", "sms-gw", `{"inputs":{"MODULE_ADVERTISE_HOST":"a\nb"}}`, nil, true, 400, false},
		"extra input":    {"operator", "sms-gw", `{"inputs":{"MODULE_ADVERTISE_HOST":"a.b","GATEWAY_ISSUER":"https://evil"}}`, nil, true, 400, false},
		"ttl too long":   {"operator", "sms-gw", `{"inputs":{"MODULE_ADVERTISE_HOST":"a.b"},"ttl_hours":25}`, nil, true, 400, false},
		"ttl zero":       {"operator", "sms-gw", `{"inputs":{"MODULE_ADVERTISE_HOST":"a.b"},"ttl_hours":0}`, nil, true, 400, false},
		"not configured": {"operator", "sms-gw", `{"inputs":{"MODULE_ADVERTISE_HOST":"a.b"}}`, nil, false, 503, false},
		"allow-list differs": {"operator", "sms-gw", `{"inputs":{"MODULE_ADVERTISE_HOST":"a.b"}}`, func(e *joinEnv) {
			_ = e.ms.InsertAllow(context.Background(), store.AllowEntry{ID: "x", SpiffeID: "spiffe://example.org/svc/sms-gw", Prefixes: []string{"/api/sms-gw"}, Names: []string{"sms-gw"}})
		}, true, 409, false},
		"auth down": {"operator", "sms-gw", `{"inputs":{"MODULE_ADVERTISE_HOST":"a.b"}}`, func(e *joinEnv) { e.auth.err = status.Error(codes.Unavailable, "down") }, true, 503, true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newJoinEnv(t, tc.configured)
			if tc.prep != nil {
				tc.prep(e)
			}
			w := do(e.s, "POST", "/gateway/v1/ops/catalogue/"+tc.module+"/join", tc.body, adminHdr(tc.who))
			if w.Code != tc.want {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if !tc.minted && len(e.auth.got) != 0 {
				t.Fatal("a refused request minted a token")
			}
			if len(e.ms.Joins) != 0 {
				t.Fatal("a refused request left a join record")
			}
		})
	}
}

func TestJoinProgress(t *testing.T) {
	e := newJoinEnv(t, true)
	w := do(e.s, "POST", "/gateway/v1/ops/catalogue/sms-gw/join", `{"inputs":{"MODULE_ADVERTISE_HOST":"sms.example.org"}}`, adminHdr("operator"))
	id := w.Header().Get("X-Join-Id")
	progress := func() map[string]any {
		t.Helper()
		w := do(e.s, "GET", "/gateway/v1/ops/catalogue/sms-gw/join/"+id, "", adminHdr("operator"))
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		var p map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &p)
		return p
	}
	if p := progress(); p["token_used"] != false || p["registered"] != false || p["version"] != "4.3.0" {
		t.Fatalf("%v", p)
	}
	e.auth.consumed[joinJTI] = time.Now()
	if p := progress(); p["token_used"] != true || p["token_used_at"] == nil {
		t.Fatalf("%v", p)
	}
	// A refused registration is shown; then the module registers.
	_ = e.aw.Emit(audit.Event{Type: audit.RegistrationRefused, Module: "sms-gw", ActorKind: "service", Outcome: "refused", Reason: "identity_not_allowed"})
	e.aw.Close()
	if p := progress(); p["last_refusal"] == nil || !strings.Contains(toJSON(p["last_refusal"]), "identity_not_allowed") {
		t.Fatalf("%v", p)
	}
	if _, err := e.reg.Register(context.Background(), "spiffe://example.org/svc/sms-gw", &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://sms"},
		Manifest: &gatewayv1.Manifest{Module: "sms-gw", DisplayName: "SMS", Version: "1.0.0", Prefixes: []string{"/api/sms-gw"},
			Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/sms-gw/x", Public: true}}, Remote: &gatewayv1.Remote{Entry: "/m/sms-gw/mf-manifest.json", Exposes: []string{"./routes"}}}}); err != nil {
		t.Fatal(err)
	}
	if p := progress(); p["registered"] != true || p["state"] != "active" {
		t.Fatalf("%v", p)
	}
	for name, path := range map[string]string{"other module": "/gateway/v1/ops/catalogue/asterisk/join/" + id, "unknown id": "/gateway/v1/ops/catalogue/sms-gw/join/0190f7c2-0000-7000-8000-000000000000"} {
		if w := do(e.s, "GET", path, "", adminHdr("operator")); w.Code != 404 {
			t.Errorf("%s → %d", name, w.Code)
		}
	}
	if w := do(e.s, "GET", "/gateway/v1/ops/catalogue/sms-gw/join/"+id, "", adminHdr("operator-only")); w.Code != 403 {
		t.Fatalf("operator read progress: %d", w.Code)
	}
}

// The view gives the wizard the entry's host inputs and min_core.
func TestCatalogueViewHasWizardFields(t *testing.T) {
	e := newJoinEnv(t, true)
	v, _ := catalogue(t, e.s, "operator")
	for _, it := range v.Items {
		if it.Module == "sms-gw" {
			if len(it.HostInputs) != 1 || it.HostInputs[0].Key != "MODULE_ADVERTISE_HOST" || it.MinCore["gateway"] != "9.0.0" || !v.CanJoin {
				t.Fatalf("%+v can_join=%v", it, v.CanJoin)
			}
			return
		}
	}
	t.Fatal("sms-gw missing")
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

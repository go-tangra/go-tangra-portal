package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	catsvc "github.com/go-tangra/go-tangra-portal/v4/internal/catalogue"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// stubRefresher records refreshes and uploads.
type stubRefresher struct {
	refreshed []string
	uploads   int
	result    catsvc.Result
}

func (s *stubRefresher) Refresh(_ context.Context, repo string) catsvc.Result {
	s.refreshed = append(s.refreshed, repo)
	r := s.result
	r.Repo = repo
	return r
}

func (s *stubRefresher) Upload(_ context.Context, entry, bundle, att []byte) catsvc.Result {
	s.uploads++
	if len(entry) == 0 || len(bundle) == 0 || len(att) == 0 {
		return catsvc.Result{Outcome: catsvc.OutcomeRefused, Error: "missing part"}
	}
	return catsvc.Result{Module: "sms-gw", Version: "4.4.0", Outcome: catsvc.OutcomeStored}
}

func entryJSON(module, version string) []byte {
	b, _ := json.Marshal(map[string]any{"schema": 1, "module": module, "version": version, "repository": "go-tangra/go-tangra-" + module,
		"display_name": strings.ToUpper(module), "category": "Communications", "summary": module + " summary", "image": "ghcr.io/go-tangra/go-tangra-" + module,
		"routes": map[string]any{"prefixes": []string{"/api/" + module}, "names": []string{module}}, "permissions": []string{},
		"bundle": map[string]any{"templates": []string{"compose.yaml"}, "sha256": strings.Repeat("a", 64), "size": 10}})
	return b
}

func sourcesServer(t *testing.T) (*Server, *memstore.Store, *stubRefresher) {
	t.Helper()
	s, _, ms, aw := catalogueServer(t)
	_ = s
	ms.Owners = []string{"go-tangra"}
	ref := &stubRefresher{result: catsvc.Result{Module: "sms-gw", Version: "4.3.0", Outcome: catsvc.OutcomeStored}}
	// Entries: orders (running 2.1.0) has 2.2.0; sms-gw is not installed.
	_ = ms.InsertEntry(context.Background(), store.CatalogueEntry{Module: "orders", Version: "2.2.0", Repo: "go-tangra/go-tangra-orders", VersionKey: 2_000_002_000_000, Entry: entryJSON("orders", "2.2.0")})
	_ = ms.InsertEntry(context.Background(), store.CatalogueEntry{Module: "sms-gw", Version: "4.3.0", Repo: "go-tangra/go-tangra-sms-gw", VersionKey: 4_000_003_000_000, Entry: entryJSON("sms-gw", "4.3.0")})
	s2 := newTestServer(t)
	reg := catalogueRegistry(t, ms, aw)
	s2.RegisterOps(OpsDeps{Reg: reg, Identity: opsIdentity{}, Audit: ms, Roles: []string{"operator"}, AdminRoles: []string{"owner", "admin"},
		Known: ms, Events: aw, Sources: ms, Refresher: ref})
	return s2, ms, ref
}

func TestCatalogueViewAddsAvailableAndUpdates(t *testing.T) {
	s, _, _ := sourcesServer(t)
	v, code := catalogue(t, s, "operator")
	if code != 200 {
		t.Fatal(code)
	}
	by := map[string]CatalogueItem{}
	for _, it := range v.Items {
		by[it.Module] = it
	}
	if o := by["orders"]; o.State != "active" || o.LatestVersion != "2.2.0" || !o.UpdateAvailable || o.Summary != "orders summary" || o.Repository != "go-tangra/go-tangra-orders" {
		t.Fatalf("orders %+v", o)
	}
	if m := by["sms-gw"]; m.State != "available" || m.Registered || m.LatestVersion != "4.3.0" || m.UpdateAvailable || !m.Installable || m.Image != "ghcr.io/go-tangra/go-tangra-sms-gw" {
		t.Fatalf("sms-gw %+v", m)
	}
	if b := by["billing"]; b.LatestVersion != "" || b.UpdateAvailable {
		t.Fatalf("billing without entry %+v", b)
	}
}

func TestCatalogueSourcesManagement(t *testing.T) {
	s, ms, ref := sourcesServer(t)
	admin := adminHdr("operator")
	w := do(s, "POST", "/gateway/v1/ops/catalogue/sources", `{"repo":"go-tangra/go-tangra-sms-gw"}`, admin)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"outcome":"stored"`) || len(ref.refreshed) != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if _, ok := ms.Sources["go-tangra/go-tangra-sms-gw"]; !ok {
		t.Fatal("source not stored")
	}
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"exists":            {`{"repo":"go-tangra/go-tangra-sms-gw"}`, 409},
		"owner not allowed": {`{"repo":"evil/go-tangra-sms-gw"}`, 400},
		"url":               {`{"repo":"https://github.com/go-tangra/x"}`, 400},
		"no slash":          {`{"repo":"go-tangra"}`, 400},
		"extra field":       {`{"repo":"go-tangra/x","y":1}`, 400},
	} {
		if w := do(s, "POST", "/gateway/v1/ops/catalogue/sources", tc.body, admin); w.Code != tc.want {
			t.Errorf("%s → %d %s, want %d", name, w.Code, w.Body, tc.want)
		}
	}
	if w := do(s, "POST", "/gateway/v1/ops/catalogue/sources", `{"repo":"go-tangra/other"}`, adminHdr("operator-only")); w.Code != 403 {
		t.Fatalf("operator added a source: %d", w.Code)
	}
	// List (operators may read).
	w = do(s, "GET", "/gateway/v1/ops/catalogue/sources", "", map[string]string{"Authorization": "Bearer operator-only"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"repo":"go-tangra/go-tangra-sms-gw"`) || !strings.Contains(w.Body.String(), `"allowed_owners":["go-tangra"]`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// Refresh on demand.
	if w := do(s, "POST", "/gateway/v1/ops/catalogue/sources/go-tangra/go-tangra-sms-gw/refresh", "", admin); w.Code != 200 || len(ref.refreshed) != 2 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(s, "POST", "/gateway/v1/ops/catalogue/sources/go-tangra/nope/refresh", "", admin); w.Code != 404 {
		t.Fatalf("refresh of unknown source → %d", w.Code)
	}
	// Remove.
	if w := do(s, "DELETE", "/gateway/v1/ops/catalogue/sources/go-tangra/go-tangra-sms-gw", "", admin); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(s, "DELETE", "/gateway/v1/ops/catalogue/sources/go-tangra/go-tangra-sms-gw", "", admin); w.Code != 404 {
		t.Fatalf("second delete → %d", w.Code)
	}
}

func TestAllowedOwners(t *testing.T) {
	s, ms, _ := sourcesServer(t)
	admin := adminHdr("operator")
	if w := do(s, "PUT", "/gateway/v1/ops/catalogue/allowed-owners", `{"owners":["go-tangra","acme"]}`, admin); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if strings.Join(ms.Owners, ",") != "go-tangra,acme" {
		t.Fatal(ms.Owners)
	}
	for name, body := range map[string]string{"empty": `{"owners":[]}`, "bad": `{"owners":["no/slash"]}`, "url": `{"owners":["https://x"]}`} {
		if w := do(s, "PUT", "/gateway/v1/ops/catalogue/allowed-owners", body, admin); w.Code != 400 {
			t.Errorf("%s → %d", name, w.Code)
		}
	}
	if w := do(s, "PUT", "/gateway/v1/ops/catalogue/allowed-owners", `{"owners":["evil"]}`, adminHdr("operator-only")); w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestCatalogueUpload(t *testing.T) {
	s, _, ref := sourcesServer(t)
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	for name, data := range map[string]string{"entry": "{}", "bundle": "PK", "attestation": "{}"} {
		fw, _ := mw.CreateFormFile(name, name)
		_, _ = fw.Write([]byte(data))
	}
	_ = mw.Close()
	r := httptest.NewRequest("POST", "https://localhost/gateway/v1/ops/catalogue/upload", body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Authorization", "Bearer operator")
	r.Header.Set("X-CSRF-Token", "x")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 || ref.uploads != 1 || !strings.Contains(w.Body.String(), `"version":"4.4.0"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	r = httptest.NewRequest("POST", "https://localhost/gateway/v1/ops/catalogue/upload", strings.NewReader("x"))
	r.Header.Set("Content-Type", "multipart/form-data; boundary=zz")
	r.Header.Set("Authorization", "Bearer operator")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("bad multipart → %d", w.Code)
	}
}

var _ = http.MethodGet
var _ = time.Second

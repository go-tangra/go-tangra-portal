package catalogue

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

func descriptor(module string) fwcat.Descriptor {
	return fwcat.Descriptor{Schema: 1, Module: module, DisplayName: strings.ToUpper(module), Category: "Communications", Summary: module + " module",
		Image: "ghcr.io/go-tangra/go-tangra-" + module, Routes: fwcat.Routes{Prefixes: []string{"/api/" + module}, Names: []string{module}},
		Bundle: fwcat.BundleSpec{Dir: "deploy/bundle", Templates: []string{"compose.yaml"}}}
}

// release is one fake GitHub release.
type release struct {
	tag                        string
	entry, bundle, attestation []byte
	noCatalogue                bool
	declaredSize               int64 // 0: real size
}

// fakeGitHub serves /repos/{owner}/{repo}/releases/latest and assets.
type fakeGitHub struct {
	mu       sync.Mutex
	releases map[string]release // lower(repo) → latest
	down     bool
	srv      *httptest.Server
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{releases: map[string]release{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/dl/") {
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/dl/"), "/", 3) // owner/repo/asset
			rel := f.releases[strings.ToLower(parts[0]+"/"+parts[1])]
			_, _ = w.Write(map[string][]byte{"catalogue-entry.json": rel.entry, "bundle.zip": rel.bundle, "catalogue.sigstore.json": rel.attestation}[parts[2]])
			return
		}
		repo := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/"), "/releases/latest")
		rel, ok := f.releases[strings.ToLower(repo)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		var assets []map[string]any
		if !rel.noCatalogue {
			for name, data := range map[string][]byte{"catalogue-entry.json": rel.entry, "bundle.zip": rel.bundle, "catalogue.sigstore.json": rel.attestation} {
				size := int64(len(data))
				if rel.declaredSize > 0 && name == "bundle.zip" {
					size = rel.declaredSize
				}
				assets = append(assets, map[string]any{"name": name, "size": size, "browser_download_url": f.srv.URL + "/dl/" + repo + "/" + name})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": rel.tag, "assets": assets})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) set(repo string, r release) {
	f.mu.Lock()
	f.releases[strings.ToLower(repo)] = r
	f.mu.Unlock()
}

type env struct {
	ctx context.Context
	vs  *ca.VirtualSigstore
	gh  *fakeGitHub
	ms  *memstore.Store
	aw  *audit.Writer
	svc *Service
	// attestations by their (opaque) bytes: the fake verify hands the real
	// verifier the matching test entity.
	att map[string]*ca.TestEntity
	n   int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{ctx: context.Background(), vs: vs, gh: newFakeGitHub(t), ms: memstore.New(), att: map[string]*ca.TestEntity{}}
	e.ms.Owners = []string{"go-tangra"}
	e.aw = audit.NewWriter(e.ms, nil)
	t.Cleanup(e.aw.Close)
	v := NewVerifier(vs)
	e.svc = &Service{Store: e.ms, GitHub: &GitHub{API: e.gh.srv.URL, Client: e.gh.srv.Client(), allowTestHost: true}, Audit: e.aw,
		Verify: func(att []byte, repo, tag string, artifacts ...[]byte) (string, error) {
			ent, ok := e.att[string(att)]
			if !ok {
				return "", fmt.Errorf("%w: unknown attestation", ErrAttestation)
			}
			return v.verifyEntity(ent, repo, tag, artifacts...)
		}}
	return e
}

// publish builds a real entry and bundle for module at version and attests
// them as repo's workflow at tag (override signer/tag to forge).
func (e *env) publish(t *testing.T, repo, module, version string, mutate func(*fwcat.Entry), signRepo, signTag string) release {
	t.Helper()
	bundle, err := fwcat.PackBundle(fstest.MapFS{"compose.yaml": {Data: []byte("services: {}\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	ent, err := fwcat.BuildEntry(descriptor(module), version, repo, []string{module + ":read"}, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&ent)
	}
	raw, _ := ent.Marshal()
	if signRepo == "" {
		signRepo = repo
	}
	if signTag == "" {
		signTag = "v" + version
	}
	te, err := e.vs.Attest("https://github.com/"+signRepo+"/.github/workflows/ci.yaml@refs/tags/"+signTag, GitHubIssuer,
		statement(t, map[string][]byte{"catalogue-entry.json": raw, "bundle.zip": bundle}))
	if err != nil {
		t.Fatal(err)
	}
	e.n++
	key := fmt.Sprintf("attestation-%d", e.n)
	e.att[key] = te
	return release{tag: "v" + version, entry: raw, bundle: bundle, attestation: []byte(key)}
}

func (e *env) source(t *testing.T, repo string) {
	t.Helper()
	if err := e.ms.AddSource(e.ctx, repo, "admin"); err != nil {
		t.Fatal(err)
	}
}

func (e *env) latest(module string) (store.CatalogueEntry, bool) {
	all, _ := e.ms.LatestEntries(e.ctx)
	for _, x := range all {
		if x.Module == module {
			return x, true
		}
	}
	return store.CatalogueEntry{}, false
}

func (e *env) sourceOf(repo string) store.CatalogueSource {
	return e.ms.Sources[strings.ToLower(repo)]
}

func auditTypes(e *env) map[string]int {
	e.aw.Close()
	out := map[string]int{}
	for _, r := range e.ms.Audit() {
		out[r.EventType+":"+r.Reason]++
	}
	return out
}

const smsRepo = "go-tangra/go-tangra-sms-gw"

func TestRefreshStoresVerifiedEntry(t *testing.T) {
	e := newEnv(t)
	e.source(t, smsRepo)
	e.gh.set(smsRepo, e.publish(t, smsRepo, "sms-gw", "4.3.0", nil, "", ""))
	res := e.svc.Refresh(e.ctx, smsRepo)
	if res.Outcome != OutcomeStored || res.Module != "sms-gw" || res.Version != "4.3.0" || res.Error != "" {
		t.Fatalf("%+v", res)
	}
	got, ok := e.latest("sms-gw")
	if !ok || got.Version != "4.3.0" || !strings.Contains(got.AttestedBy, "go-tangra-sms-gw/.github/workflows/ci.yaml@refs/tags/v4.3.0") {
		t.Fatalf("%+v", got)
	}
	if b, _ := e.ms.EntryBundle(e.ctx, "sms-gw", "4.3.0"); len(b) == 0 {
		t.Fatal("bundle not stored")
	}
	if s := e.sourceOf(smsRepo); s.Module != "sms-gw" || s.LastError != "" || s.LastCheckedAt == nil {
		t.Fatalf("%+v", s)
	}
	// The same release again is current, not an error.
	if res := e.svc.Refresh(e.ctx, smsRepo); res.Outcome != OutcomeCurrent {
		t.Fatalf("%+v", res)
	}
	if n := auditTypes(e)["catalogue_entry_verified:"]; n != 1 {
		t.Fatalf("verified audits %d", n)
	}
}

func TestRefreshRefusals(t *testing.T) {
	type tc struct {
		name    string
		prepare func(e *env) release
		want    string
	}
	for _, c := range []tc{
		{"no catalogue assets", func(e *env) release { return release{tag: "v4.3.0", noCatalogue: true} }, "no catalogue entry"},
		{"tampered entry", func(e *env) release {
			r := e.publish(t, smsRepo, "sms-gw", "4.3.0", nil, "", "")
			r.entry = []byte(strings.Replace(string(r.entry), "sms-gw module", "evil module", 1))
			return r
		}, "attestation"},
		{"signed by another repository", func(e *env) release {
			return e.publish(t, smsRepo, "sms-gw", "4.3.0", nil, "evil/go-tangra-sms-gw", "")
		}, "attestation"},
		{"entry names another repository", func(e *env) release {
			return e.publish(t, "go-tangra/go-tangra-other", "sms-gw", "4.3.0", nil, smsRepo, "")
		}, "repository"},
		{"tag differs from version", func(e *env) release {
			r := e.publish(t, smsRepo, "sms-gw", "4.3.0", nil, "", "v4.3.0")
			r.tag = "v4.3.1"
			return r
		}, "tag"},
		{"bundle larger than allowed", func(e *env) release {
			r := e.publish(t, smsRepo, "sms-gw", "4.3.0", nil, "", "")
			r.declaredSize = fwcat.MaxBundleBytes + 1
			return r
		}, "too large"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.source(t, smsRepo)
			e.gh.set(smsRepo, c.prepare(e))
			res := e.svc.Refresh(e.ctx, smsRepo)
			if res.Outcome == OutcomeStored || !strings.Contains(res.Error, c.want) {
				t.Fatalf("%+v (want error containing %q)", res, c.want)
			}
			if _, ok := e.latest("sms-gw"); ok {
				t.Fatal("refused entry stored")
			}
			if s := e.sourceOf(smsRepo); !strings.Contains(s.LastError, c.want) {
				t.Fatalf("source error %q", s.LastError)
			}
		})
	}
}

func TestDowngradeModuleChangeAndTakeover(t *testing.T) {
	e := newEnv(t)
	e.source(t, smsRepo)
	e.gh.set(smsRepo, e.publish(t, smsRepo, "sms-gw", "4.3.0", nil, "", ""))
	if res := e.svc.Refresh(e.ctx, smsRepo); res.Outcome != OutcomeStored {
		t.Fatalf("%+v", res)
	}
	// An older release offered later is refused; the stored one stays.
	e.gh.set(smsRepo, e.publish(t, smsRepo, "sms-gw", "4.2.0", nil, "", ""))
	if res := e.svc.Refresh(e.ctx, smsRepo); res.Outcome == OutcomeStored || !strings.Contains(res.Error, "older") {
		t.Fatalf("downgrade: %+v", res)
	}
	// The repository suddenly publishing another module.
	e.gh.set(smsRepo, e.publish(t, smsRepo, "asterisk", "4.4.0", nil, "", ""))
	if res := e.svc.Refresh(e.ctx, smsRepo); res.Outcome == OutcomeStored || !strings.Contains(res.Error, "publishes sms-gw") {
		t.Fatalf("module change: %+v", res)
	}
	// Another repository claiming sms-gw.
	const other = "go-tangra/sms-gw-fork"
	e.source(t, other)
	e.gh.set(other, e.publish(t, other, "sms-gw", "9.0.0", nil, "", ""))
	if res := e.svc.Refresh(e.ctx, other); res.Outcome == OutcomeStored || !strings.Contains(res.Error, "already published by") {
		t.Fatalf("takeover: %+v", res)
	}
	if got, _ := e.latest("sms-gw"); got.Version != "4.3.0" {
		t.Fatalf("stored entry changed: %+v", got)
	}
	if n := auditTypes(e); n["catalogue_entry_refused:downgrade"] != 1 || n["catalogue_entry_refused:module_changed"] != 1 || n["catalogue_entry_refused:module_taken"] != 1 {
		t.Fatalf("%v", n)
	}
}

func TestGitHubDownKeepsEntries(t *testing.T) {
	e := newEnv(t)
	e.source(t, smsRepo)
	e.gh.set(smsRepo, e.publish(t, smsRepo, "sms-gw", "4.3.0", nil, "", ""))
	e.svc.Refresh(e.ctx, smsRepo)
	e.gh.mu.Lock()
	e.gh.down = true
	e.gh.mu.Unlock()
	res := e.svc.Refresh(e.ctx, smsRepo)
	if res.Outcome != OutcomeUnavailable || res.Error == "" {
		t.Fatalf("%+v", res)
	}
	if got, ok := e.latest("sms-gw"); !ok || got.Version != "4.3.0" {
		t.Fatal("entry lost while GitHub was down")
	}
}

func TestOwnerNotAllowed(t *testing.T) {
	e := newEnv(t)
	const foreign = "someone/go-tangra-sms-gw"
	e.source(t, foreign)
	e.gh.set(foreign, e.publish(t, foreign, "sms-gw", "4.3.0", nil, "", ""))
	if res := e.svc.Refresh(e.ctx, foreign); res.Outcome == OutcomeStored || !strings.Contains(res.Error, "not an allowed owner") {
		t.Fatalf("%+v", res)
	}
}

func TestRefreshAllAndIngestUpload(t *testing.T) {
	e := newEnv(t)
	e.source(t, smsRepo)
	e.source(t, "go-tangra/go-tangra-asterisk")
	e.gh.set(smsRepo, e.publish(t, smsRepo, "sms-gw", "4.3.0", nil, "", ""))
	e.gh.set("go-tangra/go-tangra-asterisk", e.publish(t, "go-tangra/go-tangra-asterisk", "asterisk", "4.1.0", nil, "", ""))
	results := e.svc.RefreshAll(e.ctx)
	if len(results) != 2 || results[0].Outcome != OutcomeStored || results[1].Outcome != OutcomeStored {
		t.Fatalf("%+v", results)
	}
	// Upload path: same checks, for a repository that is a source.
	r := e.publish(t, smsRepo, "sms-gw", "4.4.0", nil, "", "")
	res := e.svc.Upload(e.ctx, r.entry, r.bundle, r.attestation)
	if res.Outcome != OutcomeStored || res.Version != "4.4.0" {
		t.Fatalf("%+v", res)
	}
	r = e.publish(t, smsRepo, "sms-gw", "4.5.0", nil, "", "")
	if res := e.svc.Upload(e.ctx, r.entry, []byte("PK not it"), r.attestation); res.Outcome == OutcomeStored {
		t.Fatalf("tampered upload stored: %+v", res)
	}
	r = e.publish(t, "go-tangra/not-a-source", "other", "1.0.0", nil, "", "")
	if res := e.svc.Upload(e.ctx, r.entry, r.bundle, r.attestation); res.Outcome == OutcomeStored || !strings.Contains(res.Error, "not a catalogue source") {
		t.Fatalf("%+v", res)
	}
}

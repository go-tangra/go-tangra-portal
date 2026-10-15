package docs

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/helpdocs"
)

func pngBytes(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// bundle builds a valid bundle for module; variant changes the content (and
// so the digest).
func bundle(t *testing.T, module, variant string) (*helpdocs.Bundle, []byte) {
	t.Helper()
	fsys := fstest.MapFS{
		"index.md":          {Data: []byte("---\ntitle: Start " + variant + "\nkind: guide\n---\n# Start\n\nSee [subnets](guides/subnets.md).\n\n![form](images/form.png)\n")},
		"guides/subnets.md": {Data: []byte("---\ntitle: Subnets\nkind: guide\norder: 2\ntags: [net]\nrequires: subnets:read\n---\n## Create\n\nBody.\n")},
		"operators.md":      {Data: []byte("---\ntitle: Install\nkind: reference\naudience: operator\n---\nInstall it.\n")},
		"images/form.png":   {Data: pngBytes(t)},
	}
	b, err := helpdocs.Load(fsys, module)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b, raw
}

type fakeSource struct {
	mu   sync.Mutex
	regs map[string]registry.Registration
	ch   chan registry.Event
}

func (f *fakeSource) set(module string, instances ...registry.Instance) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.regs == nil {
		f.regs = map[string]registry.Registration{}
	}
	if len(instances) == 0 {
		delete(f.regs, module)
		return
	}
	reg := registry.Registration{Module: module, Identity: "spiffe://example.org/svc/" + module, Instances: map[string]registry.Instance{}, Unhealthy: map[string]time.Time{}}
	for _, in := range instances {
		reg.Instances[in.ID] = in
	}
	f.regs[module] = reg
}

func (f *fakeSource) Registrations() []registry.Registration {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []registry.Registration
	for _, r := range f.regs {
		out = append(out, r)
	}
	return out
}

func (f *fakeSource) Get(m string) (registry.Registration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.regs[m]
	return r, ok
}

func (f *fakeSource) Watch(uint64) (<-chan registry.Event, func()) { return f.ch, func() {} }
func (f *fakeSource) Version() uint64                              { return 0 }

type fakeStore struct {
	mu     sync.Mutex
	state  map[string]store.DocsState
	pages  map[string][]store.DocPage
	assets map[string][]store.DocAsset
	fail   error
}

func newFakeStore() *fakeStore {
	return &fakeStore{state: map[string]store.DocsState{}, pages: map[string][]store.DocPage{}, assets: map[string][]store.DocAsset{}}
}

func (f *fakeStore) DocsState(_ context.Context, m string) (store.DocsState, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return store.DocsState{}, false, f.fail
	}
	s, ok := f.state[m]
	return s, ok, nil
}

func (f *fakeStore) ReplaceDocs(_ context.Context, m, d string, p []store.DocPage, a []store.DocAsset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages[m], f.assets[m] = p, a
	f.state[m] = store.DocsState{Module: m, Digest: d, PageCount: len(p)}
	return nil
}

func (f *fakeStore) RemoveDocs(_ context.Context, m string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.pages, m)
	delete(f.assets, m)
	delete(f.state, m)
	return nil
}

func (f *fakeStore) DocsFailed(_ context.Context, m, e string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.state[m]
	s.Module, s.Error = m, e
	f.state[m] = s
	return nil
}

func (f *fakeStore) ClearDocsError(_ context.Context, m string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.state[m]
	s.Error = ""
	f.state[m] = s
	return nil
}

func (f *fakeStore) get(m string) (store.DocsState, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.state[m]
	return s, ok
}

type fakeFetch struct {
	mu    sync.Mutex
	body  map[string][]byte // backend → body
	err   error
	calls int
	etags []string
}

func (f *fakeFetch) fetch(_ context.Context, t Target, etag string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.etags = append(f.etags, etag)
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.body[t.Backend]
	if !ok {
		return nil, errors.New("no such backend")
	}
	return b, nil
}

func (f *fakeFetch) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func inst(id, digest, backend string, at time.Time) registry.Instance {
	return registry.Instance{ID: id, DocsDigest: digest, Backend: registry.Backend{HTTPURL: backend}, RegisteredAt: at}
}

func TestSync(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	b1, raw1 := bundle(t, "ipam", "one")
	b2, raw2 := bundle(t, "ipam", "two")
	_, rawDNS := bundle(t, "dns", "one")
	type step struct {
		name      string
		instances []registry.Instance
		fetchErr  error
		bodies    map[string][]byte
		wantErr   string
		fetches   int // fetches during this step
		digest    string
		stateErr  bool
		notified  bool
		noState   bool
	}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"new digest is fetched and indexed, same digest is not fetched again", []step{
			{name: "first", instances: []registry.Instance{inst("i1", b1.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw1}, fetches: 1, digest: b1.Digest, notified: true},
			{name: "same", instances: []registry.Instance{inst("i1", b1.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw1}, fetches: 0, digest: b1.Digest},
			{name: "changed", instances: []registry.Instance{inst("i1", b2.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw2}, fetches: 1, digest: b2.Digest, notified: true},
		}},
		{"empty digest removes the docs", []step{
			{name: "index", instances: []registry.Instance{inst("i1", b1.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw1}, fetches: 1, digest: b1.Digest, notified: true},
			{name: "none", instances: []registry.Instance{inst("i1", "", "https://a", t0)}, fetches: 0, noState: true, notified: true},
			{name: "still none", instances: []registry.Instance{inst("i1", "", "https://a", t0)}, fetches: 0, noState: true},
		}},
		{"fetch failure keeps the old index and records the error", []step{
			{name: "index", instances: []registry.Instance{inst("i1", b1.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw1}, fetches: 1, digest: b1.Digest, notified: true},
			{name: "fail", instances: []registry.Instance{inst("i1", b2.Digest, "https://a", t0)}, fetchErr: errors.New("connection refused"), wantErr: "connection refused", fetches: 1, digest: b1.Digest, stateErr: true},
			{name: "recover", instances: []registry.Instance{inst("i1", b2.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw2}, fetches: 1, digest: b2.Digest, notified: true},
		}},
		{"a bundle for another module is refused", []step{
			{name: "mismatch", instances: []registry.Instance{inst("i1", b1.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": rawDNS}, wantErr: `module "dns"`, fetches: 1, stateErr: true},
		}},
		{"a bundle with another digest is refused", []step{
			{name: "mismatch", instances: []registry.Instance{inst("i1", b2.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw1}, wantErr: "bundle digest", fetches: 1, stateErr: true},
		}},
		{"a corrupt bundle is refused", []step{
			{name: "corrupt", instances: []registry.Instance{inst("i1", b1.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": bytes.Replace(raw1, []byte("Subnets"), []byte("Subnetz"), 1)}, wantErr: "invalid bundle", fetches: 1, stateErr: true},
		}},
		{"304 means the instance still serves the indexed bundle", []step{
			{name: "index", instances: []registry.Instance{inst("i1", b1.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw1}, fetches: 1, digest: b1.Digest, notified: true},
			{name: "304", instances: []registry.Instance{inst("i1", b2.Digest, "https://a", t0)}, fetchErr: ErrNotModified, wantErr: "still serves", fetches: 1, digest: b1.Digest, stateErr: true},
		}},
		{"rollout: the newest instance's digest wins and is fetched from an instance serving it", []step{
			{name: "rollout", instances: []registry.Instance{inst("old", b1.Digest, "https://old", t0), inst("new", b2.Digest, "https://new", t0.Add(time.Minute))},
				bodies: map[string][]byte{"https://new": raw2}, fetches: 1, digest: b2.Digest, notified: true},
		}},
		{"withdrawn module keeps its rows", []step{
			{name: "index", instances: []registry.Instance{inst("i1", b1.Digest, "https://a", t0)}, bodies: map[string][]byte{"https://a": raw1}, fetches: 1, digest: b1.Digest, notified: true},
			{name: "withdrawn", fetches: 0, digest: b1.Digest},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, st, ff := &fakeSource{}, newFakeStore(), &fakeFetch{}
			var notified []string
			x := &Indexer{Reg: src, Store: st, Fetch: ff.fetch, Notify: func(m string) { notified = append(notified, m) }}
			for _, s := range tc.steps {
				src.set("ipam", s.instances...)
				ff.body, ff.err = s.bodies, s.fetchErr
				before, nbefore := ff.count(), len(notified)
				err := x.Sync(ctx, "ipam")
				if s.wantErr == "" && err != nil || s.wantErr != "" && (err == nil || !strings.Contains(err.Error(), s.wantErr)) {
					t.Fatalf("%s: err %v, want %q", s.name, err, s.wantErr)
				}
				if got := ff.count() - before; got != s.fetches {
					t.Fatalf("%s: %d fetches, want %d", s.name, got, s.fetches)
				}
				state, found := st.get("ipam")
				if s.noState {
					if found {
						t.Fatalf("%s: state %+v after removal", s.name, state)
					}
				} else if state.Digest != s.digest || (state.Error != "") != s.stateErr {
					t.Fatalf("%s: state %+v", s.name, state)
				}
				if (len(notified) > nbefore) != s.notified {
					t.Fatalf("%s: notified %v", s.name, notified)
				}
			}
		})
	}
}

// TestSyncSendsIndexedDigest: the fetch carries the indexed digest as the
// If-None-Match value.
func TestSyncSendsIndexedDigest(t *testing.T) {
	b1, raw1 := bundle(t, "ipam", "one")
	b2, raw2 := bundle(t, "ipam", "two")
	src, st, ff := &fakeSource{}, newFakeStore(), &fakeFetch{body: map[string][]byte{"https://a": raw1}}
	x := &Indexer{Reg: src, Store: st, Fetch: ff.fetch}
	src.set("ipam", inst("i1", b1.Digest, "https://a", time.Now()))
	_ = x.Sync(context.Background(), "ipam")
	src.set("ipam", inst("i1", b2.Digest, "https://a", time.Now()))
	ff.body["https://a"] = raw2
	_ = x.Sync(context.Background(), "ipam")
	if len(ff.etags) != 2 || ff.etags[0] != "" || ff.etags[1] != b1.Digest {
		t.Fatalf("%q", ff.etags)
	}
}

func TestBuild(t *testing.T) {
	b, _ := bundle(t, "ipam", "one")
	pages, assets := Build(b)
	if len(pages) != 3 || len(assets) != 1 || assets[0].Path != "images/form.png" || assets[0].MIME != "image/png" {
		t.Fatalf("%d pages, assets %+v", len(pages), assets)
	}
	by := map[string]store.DocPage{}
	for _, p := range pages {
		by[p.Slug] = p
	}
	idx := by["index"]
	if !strings.Contains(idx.HTML, `href="/help/ipam/guides/subnets"`) || !strings.Contains(idx.HTML, `src="/gateway/v1/docs/ipam/assets/images/form.png?v=`) {
		t.Fatal(idx.HTML)
	}
	if s := by["guides/subnets"]; s.Requires != "subnets:read" || s.Order != 2 || len(s.Tags) != 1 || s.Headings != "Create" || s.Audience != "user" || s.Digest != b.Digest {
		t.Fatalf("%+v", s)
	}
	if by["operators"].Audience != "operator" || by["operators"].Kind != "reference" {
		t.Fatalf("%+v", by["operators"])
	}
}

func TestWanted(t *testing.T) {
	t0 := time.Now()
	reg := registry.Registration{Instances: map[string]registry.Instance{
		"a": inst("a", "d1", "https://a", t0),
		"b": inst("b", "d2", "https://b", t0.Add(time.Second)),
		"c": inst("c", "d2", "https://c", t0.Add(-time.Second)),
		"d": inst("d", "d2", "", t0.Add(-time.Second)),
	}, Unhealthy: map[string]time.Time{"b": t0}}
	d, serving := Wanted(reg)
	if d != "d2" || len(serving) != 2 || serving[0].ID != "c" || serving[1].ID != "b" {
		t.Fatalf("%s %+v", d, serving)
	}
	reg.Instances["e"] = inst("e", "", "https://e", t0.Add(time.Hour))
	if d, s := Wanted(reg); d != "" || s != nil {
		t.Fatalf("newest instance ships no docs: %s %+v", d, s)
	}
	if d, _ := Wanted(registry.Registration{}); d != "" {
		t.Fatal(d)
	}
}

// TestRun: the indexer reconciles at start, follows registry events and
// retries a failed fetch with backoff.
func TestRun(t *testing.T) {
	b1, raw1 := bundle(t, "ipam", "one")
	b2, raw2 := bundle(t, "ipam", "two")
	src := &fakeSource{ch: make(chan registry.Event, 4)}
	st, ff := newFakeStore(), &fakeFetch{body: map[string][]byte{"https://a": raw1}}
	src.set("ipam", inst("i1", b1.Digest, "https://a", time.Now()))
	n := &Notifier{}
	events, cancelSub := n.Subscribe()
	defer cancelSub()
	x := &Indexer{Reg: src, Store: st, Fetch: ff.fetch, Notify: n.Publish, RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- x.Run(ctx) }()
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("initial index", func() bool { s, _ := st.get("ipam"); return s.Digest == b1.Digest })
	if m := <-events; m != "ipam" {
		t.Fatal(m)
	}
	// A new release whose instance is not reachable yet: retried until it is.
	ff.mu.Lock()
	ff.err = errors.New("unreachable")
	ff.mu.Unlock()
	src.set("ipam", inst("i1", b2.Digest, "https://a", time.Now()))
	src.ch <- registry.Event{Kind: registry.EventUpdated, Module: "ipam"}
	waitFor("error recorded", func() bool { s, _ := st.get("ipam"); return s.Error != "" && s.Digest == b1.Digest })
	ff.mu.Lock()
	ff.err, ff.body["https://a"] = nil, raw2
	ff.mu.Unlock()
	waitFor("retry", func() bool { s, _ := st.get("ipam"); return s.Digest == b2.Digest && s.Error == "" })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	x.Trigger("ipam") // after Run: ignored
}

func TestNotifier(t *testing.T) {
	n := &Notifier{}
	a, cancelA := n.Subscribe()
	b, cancelB := n.Subscribe()
	cancelB()
	cancelB()
	n.Publish("ipam")
	if m := <-a; m != "ipam" {
		t.Fatal(m)
	}
	select {
	case m := <-b:
		t.Fatalf("cancelled subscriber got %q", m)
	default:
	}
	for i := 0; i < 100; i++ {
		n.Publish("x") // never blocks on a full subscriber
	}
	cancelA()
}

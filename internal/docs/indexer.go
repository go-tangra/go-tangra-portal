// Package docs indexes module documentation (help pages). Modules ship a
// helpdocs bundle in their binaries and announce its digest when they
// register; the indexer fetches the bundle from a module instance over the
// mTLS mesh whenever the wanted digest differs from the indexed one, renders
// and sanitizes every page, and replaces the module's rows in the store in one
// transaction. The browser API (internal/httpapi) reads the store.
//
// The indexer runs beside the registry like the known-module recorder: it
// follows the registry's event stream, reconciles every registered module at
// start and periodically, and never blocks registration or routing.
package docs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/helpdocs"
)

// Defaults.
const (
	DefaultInterval   = 5 * time.Minute  // full reconcile
	DefaultTimeout    = 30 * time.Second // one bundle fetch
	DefaultRetryMin   = 10 * time.Second // first retry after a failure
	DefaultRetryMax   = 10 * time.Minute // retry backoff cap
	maxErrorText      = 500
	maxBundleOverhead = helpdocs.MaxTotalBytes // JSON + base64 framing on top of the content
)

// MaxBundleBytes caps a fetched bundle: helpdocs.Decode refuses anything
// larger, so reading more is pointless.
const MaxBundleBytes = helpdocs.MaxTotalBytes + maxBundleOverhead

// Source is the part of the registry the indexer follows.
type Source interface {
	Registrations() []registry.Registration
	Get(module string) (registry.Registration, bool)
	Watch(cursor uint64) (<-chan registry.Event, func())
	Version() uint64
}

// Store keeps the indexed documentation.
type Store interface {
	DocsState(ctx context.Context, module string) (store.DocsState, bool, error)
	ReplaceDocs(ctx context.Context, module, digest string, pages []store.DocPage, assets []store.DocAsset) error
	RemoveDocs(ctx context.Context, module string) error
	DocsFailed(ctx context.Context, module, errText string) error
	ClearDocsError(ctx context.Context, module string) error
}

// Target is the instance a bundle is fetched from.
type Target struct {
	Module   string
	Identity string // the module's SPIFFE ID (the peer the client must verify)
	Backend  string // the instance's HTTP base URL
	Instance string
}

// ErrNotModified is returned by a Fetcher when the instance answered 304 to
// If-None-Match: it still serves the bundle that is indexed.
var ErrNotModified = errors.New("docs: bundle not modified")

// Fetcher GETs helpdocs.BundlePath from an instance and returns the body
// (at most MaxBundleBytes). etag is the indexed digest ("" for none), sent
// as If-None-Match.
type Fetcher func(ctx context.Context, t Target, etag string) ([]byte, error)

// Indexer keeps the store's documentation in step with the registry.
type Indexer struct {
	Reg   Source
	Store Store
	Fetch Fetcher
	// Notify is called after a module's documentation was (re)indexed or
	// removed (the shell refreshes its help views). It must not block.
	Notify   func(module string)
	Interval time.Duration // full reconcile; default DefaultInterval
	Timeout  time.Duration // per fetch; default DefaultTimeout
	RetryMin time.Duration // default DefaultRetryMin
	RetryMax time.Duration // default DefaultRetryMax
	Logger   *slog.Logger

	mu      sync.Mutex
	running map[string]bool          // a sync is in flight (single flight per module)
	again   map[string]bool          // re-run once the in-flight sync ends
	backoff map[string]time.Duration // current retry delay after failures
	retry   map[string]*time.Timer
	seen    map[string]string // indexed digest last observed, for change notices
	ctx     context.Context
	wg      sync.WaitGroup
}

// Wanted is the digest the module's documentation should be at, and the
// instances serving it. Instances may disagree during a rollout; the newest
// registered instance wins (it is the release being rolled out, and a
// rollback re-registers the old release, making it the newest again).
func Wanted(reg registry.Registration) (digest string, serving []registry.Instance) {
	var newest registry.Instance
	found := false
	for _, in := range reg.Instances {
		if !found || in.RegisteredAt.After(newest.RegisteredAt) || in.RegisteredAt.Equal(newest.RegisteredAt) && in.ID > newest.ID {
			newest, found = in, true
		}
	}
	if !found || newest.DocsDigest == "" {
		return "", nil
	}
	for _, in := range reg.Instances {
		if in.DocsDigest == newest.DocsDigest && in.Backend.HTTPURL != "" {
			serving = append(serving, in)
		}
	}
	// Healthy instances first, then by id (deterministic).
	sort.Slice(serving, func(i, j int) bool {
		_, bi := reg.Unhealthy[serving[i].ID]
		_, bj := reg.Unhealthy[serving[j].ID]
		if bi != bj {
			return !bi
		}
		return serving[i].ID < serving[j].ID
	})
	return newest.DocsDigest, serving
}

// Run reconciles every registered module, then follows registry events and
// reconciles periodically until ctx ends. A closed event stream (overflow) is
// re-subscribed and followed by a full reconcile.
func (x *Indexer) Run(ctx context.Context) error {
	x.mu.Lock()
	x.ctx = ctx
	x.mu.Unlock()
	interval := x.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	defer x.wait()
	for {
		events, stop := x.Reg.Watch(x.Reg.Version())
		x.reconcile()
		done := x.follow(ctx, events, tick.C)
		stop()
		if done {
			return ctx.Err()
		}
	}
}

func (x *Indexer) follow(ctx context.Context, events <-chan registry.Event, tick <-chan time.Time) bool {
	for {
		select {
		case <-ctx.Done():
			return true
		case <-tick:
			x.reconcile()
		case ev, ok := <-events:
			if !ok {
				return false
			}
			// "updated" fires on every re-registration and carries no
			// digest: always compare. Withdrawn modules keep their rows
			// (hidden from search until they register again).
			if ev.Kind == registry.EventRegistered || ev.Kind == registry.EventUpdated {
				x.Trigger(ev.Module)
			}
		}
	}
}

// reconcile triggers every registered module.
func (x *Indexer) reconcile() {
	for _, reg := range x.Reg.Registrations() {
		x.Trigger(reg.Module)
	}
}

// Trigger schedules a sync of module in the background: at most one runs per
// module; a trigger during a run makes it run once more afterwards. Before
// Run has started it does nothing.
func (x *Indexer) Trigger(module string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.ctx == nil || x.ctx.Err() != nil {
		return
	}
	if x.running == nil {
		x.running, x.again = map[string]bool{}, map[string]bool{}
	}
	if x.running[module] {
		x.again[module] = true
		return
	}
	x.running[module] = true
	ctx := x.ctx
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		for {
			err := x.Sync(ctx, module)
			x.scheduleRetry(module, err)
			x.mu.Lock()
			if !x.again[module] || ctx.Err() != nil {
				delete(x.running, module)
				delete(x.again, module)
				x.mu.Unlock()
				return
			}
			delete(x.again, module)
			x.mu.Unlock()
		}
	}()
}

// scheduleRetry arms (failure, doubling up to RetryMax) or resets (success)
// the module's retry.
func (x *Indexer) scheduleRetry(module string, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.backoff == nil {
		x.backoff, x.retry = map[string]time.Duration{}, map[string]*time.Timer{}
	}
	if t := x.retry[module]; t != nil {
		t.Stop()
		delete(x.retry, module)
	}
	if err == nil || x.ctx == nil || x.ctx.Err() != nil {
		delete(x.backoff, module)
		return
	}
	lo, hi := x.RetryMin, x.RetryMax
	if lo <= 0 {
		lo = DefaultRetryMin
	}
	if hi <= 0 {
		hi = DefaultRetryMax
	}
	d := x.backoff[module]
	if d == 0 {
		d = lo
	} else if d *= 2; d > hi {
		d = hi
	}
	x.backoff[module] = d
	x.retry[module] = time.AfterFunc(d, func() { x.Trigger(module) })
}

// wait stops retries and waits for in-flight syncs.
func (x *Indexer) wait() {
	x.mu.Lock()
	for m, t := range x.retry {
		t.Stop()
		delete(x.retry, m)
	}
	x.mu.Unlock()
	x.wg.Wait()
}

// Sync brings one module's documentation to the wanted digest: nothing when
// it is already indexed, removal when the module ships none, otherwise fetch,
// verify, render and replace. A module that is not registered keeps its rows.
// On failure the previous index stays and the error is recorded.
func (x *Indexer) Sync(ctx context.Context, module string) error {
	reg, ok := x.Reg.Get(module)
	if !ok {
		return nil
	}
	wanted, serving := Wanted(reg)
	st, found, err := x.Store.DocsState(ctx, module)
	if err != nil {
		x.logger().Warn("docs: store unavailable", "module", module)
		return err
	}
	if wanted == "" {
		if !found {
			x.observe(module, "")
			return nil
		}
		if err := x.Store.RemoveDocs(ctx, module); err != nil {
			x.logger().Warn("docs: store unavailable", "module", module)
			return err
		}
		x.logger().Info("docs: removed", "module", module)
		x.changed(module, "")
		return nil
	}
	if found && st.Digest == wanted {
		if st.Error != "" {
			_ = x.Store.ClearDocsError(ctx, module) // an older failure for a digest no longer wanted
		}
		x.observe(module, st.Digest)
		return nil
	}
	err = x.index(ctx, module, wanted, st.Digest, serving)
	if err != nil {
		text := err.Error()
		if len(text) > maxErrorText {
			text = text[:maxErrorText]
		}
		x.logger().Warn("docs: indexing failed; keeping the previous index", "module", module, "digest", wanted, "err", text)
		if serr := x.Store.DocsFailed(ctx, module, text); serr != nil {
			x.logger().Warn("docs: store unavailable", "module", module)
		}
		return err
	}
	x.changed(module, wanted)
	return nil
}

// index fetches, verifies, renders and stores one bundle.
func (x *Indexer) index(ctx context.Context, module, wanted, have string, serving []registry.Instance) error {
	if len(serving) == 0 {
		return errors.New("no instance with an HTTP backend serves the wanted bundle")
	}
	reg, _ := x.Reg.Get(module)
	in := serving[0]
	timeout := x.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	fctx, cancel := context.WithTimeout(ctx, timeout)
	body, err := x.Fetch(fctx, Target{Module: module, Identity: reg.Identity, Backend: in.Backend.HTTPURL, Instance: in.ID}, have)
	cancel()
	if errors.Is(err, ErrNotModified) {
		return fmt.Errorf("instance %s still serves the indexed bundle, not %s", in.ID, short(wanted))
	}
	if err != nil {
		return fmt.Errorf("fetch from instance %s: %w", in.ID, err)
	}
	b, err := helpdocs.Decode(body)
	if err != nil {
		return err
	}
	if b.Module != module {
		return fmt.Errorf("bundle is for module %q", b.Module)
	}
	if b.Digest != wanted {
		return fmt.Errorf("bundle digest %s, registered %s", short(b.Digest), short(wanted))
	}
	pages, assets := Build(b)
	if err := x.Store.ReplaceDocs(ctx, module, wanted, pages, assets); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	x.logger().Info("docs: indexed", "module", module, "digest", wanted, "pages", len(pages), "assets", len(assets))
	return nil
}

// Build renders a verified bundle into store rows.
func Build(b *helpdocs.Bundle) ([]store.DocPage, []store.DocAsset) {
	site := Site{Module: b.Module, Pages: make(map[string]bool, len(b.Pages)), Assets: make(map[string]string, len(b.Assets))}
	for _, p := range b.Pages {
		site.Pages[p.Slug] = true
	}
	assets := make([]store.DocAsset, 0, len(b.Assets))
	for _, a := range b.Assets {
		site.Assets[a.Path] = a.SHA256
		assets = append(assets, store.DocAsset{Module: b.Module, Path: a.Path, MIME: a.MIME, SHA256: a.SHA256, Bytes: a.Data})
	}
	pages := make([]store.DocPage, 0, len(b.Pages))
	for _, p := range b.Pages {
		r := Render(site, p.Slug, p.Markdown)
		audience := string(p.Audience)
		if audience != string(helpdocs.AudienceUser) && audience != "" {
			audience = string(helpdocs.AudienceOperator) // anything unknown is the narrower audience
		}
		pages = append(pages, store.DocPage{Module: b.Module, Slug: p.Slug, Lang: p.Lang, Kind: string(p.Kind), Audience: audience,
			Title: clean(p.Title), Summary: clean(p.Summary), Tags: p.Tags, Requires: p.Requires, Order: p.Order,
			Headings: r.Headings, Outline: r.Outline, Body: r.Body, HTML: r.HTML, Digest: b.Digest})
	}
	return pages, assets
}

// changed records the indexed digest and announces the change.
func (x *Indexer) changed(module, digest string) {
	x.mu.Lock()
	if x.seen == nil {
		x.seen = map[string]string{}
	}
	x.seen[module] = digest
	x.mu.Unlock()
	if x.Notify != nil {
		x.Notify(module)
	}
}

// observe notices an index another gateway replica wrote (the store is
// shared): browsers connected here are told too. The first observation after
// start is not a change.
func (x *Indexer) observe(module, digest string) {
	x.mu.Lock()
	if x.seen == nil {
		x.seen = map[string]string{}
	}
	prev, known := x.seen[module]
	x.seen[module] = digest
	x.mu.Unlock()
	if known && prev != digest && x.Notify != nil {
		x.Notify(module)
	}
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func (x *Indexer) logger() *slog.Logger {
	if x.Logger != nil {
		return x.Logger
	}
	return slog.Default()
}

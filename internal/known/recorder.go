// Package known keeps the gateway's memory of the modules it has seen
// register (gateway module catalogue, phase 1). The leased registry forgets a
// module when its last instance leaves; the recorder copies what it needs into
// the store so a module that is installed but down stays visible.
//
// The recorder runs beside the registry: it follows the registry's event
// stream and refreshes registered modules periodically, from its own
// goroutine. Registration, renewal and routing never wait for it or its store.
package known

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// DefaultInterval is how often registered modules are refreshed: last seen
// is at most this old while a module stays registered.
const DefaultInterval = 5 * time.Minute

// Store records that a module was seen (store.SeeKnown semantics).
type Store interface {
	SeeKnown(ctx context.Context, m store.KnownModule) error
}

// Source is the part of the registry the recorder follows.
type Source interface {
	Registrations() []registry.Registration
	Get(module string) (registry.Registration, bool)
	Watch(cursor uint64) (<-chan registry.Event, func())
	Version() uint64
}

// Recorder writes known modules from registry changes.
type Recorder struct {
	Reg      Source
	Store    Store
	Interval time.Duration // default DefaultInterval
	Now      func() time.Time
	Logger   *slog.Logger

	mu      sync.Mutex
	last    map[string]store.KnownModule // last record per module, for withdrawals
	failing bool                         // a store failure is being reported
}

// Run records the current registrations, then follows the event stream and
// refreshes every Interval until ctx ends. A closed stream (overflow) is
// re-subscribed and followed by a full refresh.
func (r *Recorder) Run(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		events, stop := r.Reg.Watch(r.Reg.Version())
		r.Refresh(ctx)
		if done := r.follow(ctx, events, tick.C); done {
			stop()
			return ctx.Err()
		}
		stop()
	}
}

// follow handles events and ticks until ctx ends (true) or the stream closes.
func (r *Recorder) follow(ctx context.Context, events <-chan registry.Event, tick <-chan time.Time) bool {
	for {
		select {
		case <-ctx.Done():
			return true
		case <-tick:
			r.Refresh(ctx)
		case ev, ok := <-events:
			if !ok {
				return false
			}
			r.handle(ctx, ev)
		}
	}
}

func (r *Recorder) handle(ctx context.Context, ev registry.Event) {
	switch ev.Kind {
	case registry.EventRegistered, registry.EventUpdated:
		if reg, ok := r.Reg.Get(ev.Module); ok {
			r.see(ctx, record(reg, r.now()))
		}
	case registry.EventWithdrawn:
		// The registration is gone: record the moment from the last record.
		r.mu.Lock()
		m, ok := r.last[ev.Module]
		r.mu.Unlock()
		if ok {
			if !ev.TS.IsZero() {
				m.LastSeenAt = ev.TS.UTC()
			} else {
				m.LastSeenAt = r.now()
			}
			r.see(ctx, m)
		}
	}
}

// Refresh records every registered module now.
func (r *Recorder) Refresh(ctx context.Context) {
	now := r.now()
	for _, reg := range r.Reg.Registrations() {
		r.see(ctx, record(reg, now))
	}
}

func (r *Recorder) see(ctx context.Context, m store.KnownModule) {
	r.mu.Lock()
	if r.last == nil {
		r.last = map[string]store.KnownModule{}
	}
	r.last[m.Module] = m
	r.mu.Unlock()
	err := r.Store.SeeKnown(ctx, m)
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case err != nil && !r.failing:
		// The error itself is not logged: store errors may carry connection detail.
		r.failing = true
		r.logger().Warn("known modules: store unavailable; retrying on the next refresh", "module", m.Module)
	case err == nil && r.failing:
		r.failing = false
		r.logger().Info("known modules: store available again")
	}
}

// record is the known-module row for a live registration seen at now.
func record(reg registry.Registration, now time.Time) store.KnownModule {
	version := ""
	if vs := reg.BuildVersions(); len(vs) > 0 {
		version = vs[len(vs)-1] // sorted oldest first
	}
	return store.KnownModule{Module: reg.Module, Identity: reg.Identity, DisplayName: reg.Manifest.DisplayName,
		LastVersion: version, ManifestHash: reg.Hash, LastSeenAt: now}
}

func (r *Recorder) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Recorder) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}

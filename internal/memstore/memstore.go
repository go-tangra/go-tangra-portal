// Package memstore is an in-memory implementation of the store-facing
// interfaces for unit tests, fuzzing and single-process development.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/go-freya/freya/services/gateway/internal/store"
)

// Store keeps everything in maps; exported fields are for test setup.
type Store struct {
	mu        sync.Mutex
	Allow     map[string]store.AllowEntry // by id
	Marks     map[string]store.Mark       // by id
	AuditRows []store.AuditRow
	Now       func() time.Time
	// Fail, when set, is returned by every method (failure injection).
	Fail error
}

// New returns an empty store.
func New() *Store {
	return &Store{Allow: map[string]store.AllowEntry{}, Marks: map[string]store.Mark{}, Now: time.Now}
}

// InsertAllow adds an entry; a second active entry for the same identity conflicts.
func (m *Store) InsertAllow(_ context.Context, e store.AllowEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, x := range m.Allow {
		if x.SpiffeID == e.SpiffeID && x.RevokedAt == nil {
			return store.ErrConflict
		}
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = m.Now()
	}
	m.Allow[e.ID] = e
	return nil
}

// AllowBySpiffeID returns the active entry for an identity.
func (m *Store) AllowBySpiffeID(_ context.Context, id string) (store.AllowEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return store.AllowEntry{}, m.Fail
	}
	for _, x := range m.Allow {
		if x.SpiffeID == id && x.RevokedAt == nil {
			return x, nil
		}
	}
	return store.AllowEntry{}, store.ErrNotFound
}

// ListAllow lists all entries ordered by identity.
func (m *Store) ListAllow(_ context.Context) ([]store.AllowEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	out := make([]store.AllowEntry, 0, len(m.Allow))
	for _, x := range m.Allow {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SpiffeID < out[j].SpiffeID })
	return out, nil
}

// RevokeAllow retires an entry.
func (m *Store) RevokeAllow(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	x, ok := m.Allow[id]
	if !ok || x.RevokedAt != nil {
		return store.ErrNotFound
	}
	t := m.Now()
	x.RevokedAt = &t
	m.Allow[id] = x
	return nil
}

// SetMark replaces the active mark of a module.
func (m *Store) SetMark(_ context.Context, mk store.Mark) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	now := m.Now()
	for id, x := range m.Marks {
		if x.Module == mk.Module && x.ClearedAt == nil {
			x.ClearedAt = &now
			m.Marks[id] = x
		}
	}
	if mk.SetAt.IsZero() {
		mk.SetAt = now
	}
	m.Marks[mk.ID] = mk
	return nil
}

// ClearMark clears the active mark of a module.
func (m *Store) ClearMark(_ context.Context, module string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	now := m.Now()
	cleared := false
	for id, x := range m.Marks {
		if x.Module == module && x.ClearedAt == nil {
			x.ClearedAt = &now
			m.Marks[id] = x
			cleared = true
		}
	}
	if !cleared {
		return store.ErrNotFound
	}
	return nil
}

// ActiveMarks lists modules with an active mark.
func (m *Store) ActiveMarks(_ context.Context) ([]store.Mark, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	var out []store.Mark
	for _, x := range m.Marks {
		if x.ClearedAt == nil {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// InsertAuditRows appends rows (audit.Inserter).
func (m *Store) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.AuditRows = append(m.AuditRows, rows...)
	return nil
}

// QueryAudit filters rows like the SQL repository (newest first).
func (m *Store) QueryAudit(_ context.Context, module, eventType string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	var out []store.AuditRow
	for _, r := range m.AuditRows {
		if (module != "" && r.Module != module) || (eventType != "" && r.EventType != eventType) || r.TS.Before(from) || r.TS.After(to) || (!cursor.IsZero() && !r.TS.Before(cursor)) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Audit returns a copy of the audit rows (test helper).
func (m *Store) Audit() []store.AuditRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.AuditRow(nil), m.AuditRows...)
}

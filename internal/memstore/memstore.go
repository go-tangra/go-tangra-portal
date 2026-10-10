// Package memstore is an in-memory implementation of the store-facing
// interfaces for unit tests, fuzzing and single-process development.
package memstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/listquery"
)

// Store keeps everything in maps; exported fields are for test setup.
type Store struct {
	mu        sync.Mutex
	Allow     map[string]store.AllowEntry  // by id
	Marks     map[string]store.Mark        // by id
	Known     map[string]store.KnownModule // by module
	Owners    []string
	Sources   map[string]store.CatalogueSource // by lower(repo)
	Entries   []store.CatalogueEntry
	Joins     map[string]store.CatalogueJoin
	AuditRows []store.AuditRow
	auditSeq  int64
	Now       func() time.Time
	// Fail, when set, is returned by every method (failure injection).
	Fail error
}

// New returns an empty store.
func New() *Store {
	return &Store{Allow: map[string]store.AllowEntry{}, Marks: map[string]store.Mark{}, Known: map[string]store.KnownModule{}, Sources: map[string]store.CatalogueSource{}, Joins: map[string]store.CatalogueJoin{}, Now: time.Now}
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

// SeeKnown mirrors store.SeeKnown.
func (m *Store) SeeKnown(_ context.Context, k store.KnownModule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	x, ok := m.Known[k.Module]
	if !ok {
		k.FirstSeenAt, k.Expected = k.LastSeenAt, true
		m.Known[k.Module] = k
		return nil
	}
	x.Identity, x.DisplayName, x.ManifestHash, x.ForgottenAt = k.Identity, k.DisplayName, k.ManifestHash, nil
	if k.LastVersion != "" {
		x.LastVersion = k.LastVersion
	}
	if k.LastSeenAt.After(x.LastSeenAt) {
		x.LastSeenAt = k.LastSeenAt
	}
	m.Known[k.Module] = x
	return nil
}

// ListKnown mirrors store.ListKnown.
func (m *Store) ListKnown(_ context.Context) ([]store.KnownModule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	var out []store.KnownModule
	for _, x := range m.Known {
		if x.ForgottenAt == nil {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// SetKnownExpected mirrors store.SetKnownExpected.
func (m *Store) SetKnownExpected(_ context.Context, module string, expected bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	x, ok := m.Known[module]
	if !ok || x.ForgottenAt != nil {
		return store.ErrNotFound
	}
	x.Expected = expected
	m.Known[module] = x
	return nil
}

// ForgetKnown mirrors store.ForgetKnown.
func (m *Store) ForgetKnown(_ context.Context, module string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	x, ok := m.Known[module]
	if !ok || x.ForgottenAt != nil {
		return store.ErrNotFound
	}
	now := m.Now()
	x.ForgottenAt = &now
	m.Known[module] = x
	return nil
}

// ListAllowedOwners mirrors store.ListAllowedOwners.
func (m *Store) ListAllowedOwners(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	out := append([]string{}, m.Owners...)
	sort.Strings(out)
	return out, nil
}

// ReplaceAllowedOwners mirrors store.ReplaceAllowedOwners.
func (m *Store) ReplaceAllowedOwners(_ context.Context, owners []string, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.Owners = append([]string{}, owners...)
	return nil
}

// SeedAllowedOwners mirrors store.SeedAllowedOwners.
func (m *Store) SeedAllowedOwners(ctx context.Context, owners []string) error {
	m.mu.Lock()
	empty := len(m.Owners) == 0
	m.mu.Unlock()
	if !empty {
		return nil
	}
	return m.ReplaceAllowedOwners(ctx, owners, "config")
}

// ListSources mirrors store.ListSources.
func (m *Store) ListSources(context.Context) ([]store.CatalogueSource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	out := []store.CatalogueSource{}
	for _, s := range m.Sources {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, nil
}

// AddSource mirrors store.AddSource.
func (m *Store) AddSource(_ context.Context, repo, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if _, ok := m.Sources[strings.ToLower(repo)]; ok {
		return store.ErrConflict
	}
	m.Sources[strings.ToLower(repo)] = store.CatalogueSource{Repo: repo, AddedBy: by, AddedAt: m.Now()}
	return nil
}

// RemoveSource mirrors store.RemoveSource.
func (m *Store) RemoveSource(_ context.Context, repo string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if _, ok := m.Sources[strings.ToLower(repo)]; !ok {
		return store.ErrNotFound
	}
	delete(m.Sources, strings.ToLower(repo))
	return nil
}

// SourceChecked mirrors store.SourceChecked (module unique across sources).
func (m *Store) SourceChecked(_ context.Context, repo, module, errText string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	key := strings.ToLower(repo)
	s, ok := m.Sources[key]
	if !ok {
		return nil
	}
	if module != "" {
		for k, o := range m.Sources {
			if k != key && o.Module == module {
				return store.ErrConflict
			}
		}
		s.Module = module
	}
	now := m.Now()
	s.LastCheckedAt, s.LastError = &now, errText
	m.Sources[key] = s
	return nil
}

// InsertEntry mirrors store.InsertEntry.
func (m *Store) InsertEntry(_ context.Context, e store.CatalogueEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, x := range m.Entries {
		if x.Module == e.Module && x.Version == e.Version {
			return store.ErrConflict
		}
	}
	m.Entries = append(m.Entries, e)
	return nil
}

// LatestEntries mirrors store.LatestEntries (bundles left out).
func (m *Store) LatestEntries(context.Context) ([]store.CatalogueEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	best := map[string]store.CatalogueEntry{}
	for _, e := range m.Entries {
		if b, ok := best[e.Module]; !ok || e.VersionKey > b.VersionKey {
			e.Bundle = nil
			best[e.Module] = e
		}
	}
	out := []store.CatalogueEntry{}
	for _, e := range best {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// EntryBundle mirrors store.EntryBundle.
func (m *Store) EntryBundle(_ context.Context, module, version string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	for _, e := range m.Entries {
		if e.Module == module && e.Version == version {
			return e.Bundle, nil
		}
	}
	return nil, store.ErrNotFound
}

// InsertJoin mirrors store.InsertJoin.
func (m *Store) InsertJoin(_ context.Context, j store.CatalogueJoin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.Joins[j.ID] = j
	return nil
}

// GetJoin mirrors store.GetJoin.
func (m *Store) GetJoin(_ context.Context, id string) (store.CatalogueJoin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return store.CatalogueJoin{}, m.Fail
	}
	j, ok := m.Joins[id]
	if !ok || !j.ExpiresAt.After(m.Now().Add(-24*time.Hour)) {
		return store.CatalogueJoin{}, store.ErrNotFound
	}
	return j, nil
}

// InsertAuditRows appends rows (audit.Inserter).
func (m *Store) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, r := range rows {
		m.auditSeq++
		r.ID = m.auditSeq
		m.AuditRows = append(m.AuditRows, r)
	}
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

// PageAudit filters, sorts and pages rows like the SQL repository.
func (m *Store) PageAudit(_ context.Context, q store.AuditQuery, req listquery.Request) ([]store.AuditRow, int, listquery.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, 0, req, m.Fail
	}
	var match []*store.AuditRow
	for i := range m.AuditRows {
		r := &m.AuditRows[i]
		if (q.Module != "" && r.Module != q.Module) || (q.EventType != "" && r.EventType != q.EventType) || r.TS.Before(q.From) || r.TS.After(q.To) {
			continue
		}
		match = append(match, r)
	}
	listquery.SortSlice(match, req, func(r *store.AuditRow, field string) any {
		switch field {
		case "module":
			return r.Module
		case "event_type":
			return r.EventType
		}
		return r.TS
	}, func(r *store.AuditRow) string { return fmt.Sprintf("%020d", r.ID) })
	page, total, applied := listquery.Window(match, req)
	out := make([]store.AuditRow, 0, len(page))
	for _, r := range page {
		out = append(out, *r)
	}
	return out, total, applied, nil
}

// Audit returns a copy of the audit rows (test helper).
func (m *Store) Audit() []store.AuditRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.AuditRow(nil), m.AuditRows...)
}

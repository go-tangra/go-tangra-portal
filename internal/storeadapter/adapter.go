// Package storeadapter binds the SQL store to the interfaces the registry and
// the operations API consume (memstore implements the same set for tests).
package storeadapter

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/listquery"
)

// Adapter wraps a *store.Store.
type Adapter struct{ St *store.Store }

// New returns an adapter.
func New(st *store.Store) *Adapter { return &Adapter{St: st} }

// AllowBySpiffeID implements registry.AllowStore.
func (a *Adapter) AllowBySpiffeID(ctx context.Context, id string) (out store.AllowEntry, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.AllowBySpiffeID(ctx, tx, id); return err })
	return
}

// ActiveMarks implements registry.MarkStore.
func (a *Adapter) ActiveMarks(ctx context.Context) (out []store.Mark, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.ActiveMarks(ctx, tx); return err })
	return
}

// InsertAllow adds an allow-list entry.
func (a *Adapter) InsertAllow(ctx context.Context, e store.AllowEntry) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.InsertAllow(ctx, tx, e) })
}

// ListAllow lists entries.
func (a *Adapter) ListAllow(ctx context.Context) (out []store.AllowEntry, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.ListAllow(ctx, tx); return err })
	return
}

// RevokeAllow retires an entry.
func (a *Adapter) RevokeAllow(ctx context.Context, id string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.RevokeAllow(ctx, tx, id, time.Now().UTC()) })
}

// SetMark records a mark.
func (a *Adapter) SetMark(ctx context.Context, m store.Mark) error {
	if m.SetAt.IsZero() {
		m.SetAt = time.Now().UTC()
	}
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.SetMark(ctx, tx, m) })
}

// ClearMark clears the active mark of a module.
func (a *Adapter) ClearMark(ctx context.Context, module string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.ClearMark(ctx, tx, module, time.Now().UTC()) })
}

// PageAudit implements audit.Querier: count and page in one transaction.
func (a *Adapter) PageAudit(ctx context.Context, q store.AuditQuery, req listquery.Request) (out []store.AuditRow, total int, applied listquery.Request, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error {
		out, total, applied, err = store.PageAudit(ctx, tx, q, req)
		return err
	})
	return
}

// QueryAudit implements audit.Querier.
func (a *Adapter) QueryAudit(ctx context.Context, module, et string, from, to, cursor time.Time, limit int) (out []store.AuditRow, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error {
		out, err = store.QueryAudit(ctx, tx, module, et, from, to, cursor, limit)
		return err
	})
	return
}

// SeeKnown implements known.Store.
func (a *Adapter) SeeKnown(ctx context.Context, m store.KnownModule) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.SeeKnown(ctx, tx, m) })
}

// ListKnown lists the known modules.
func (a *Adapter) ListKnown(ctx context.Context) (out []store.KnownModule, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.ListKnown(ctx, tx); return err })
	return
}

// SetKnownExpected sets whether a known module should be running.
func (a *Adapter) SetKnownExpected(ctx context.Context, module string, expected bool) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.SetKnownExpected(ctx, tx, module, expected) })
}

// ForgetKnown removes a module from the known list.
func (a *Adapter) ForgetKnown(ctx context.Context, module string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.ForgetKnown(ctx, tx, module, time.Now().UTC()) })
}

// ListAllowedOwners implements catalogue.Store.
func (a *Adapter) ListAllowedOwners(ctx context.Context) (out []string, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.ListAllowedOwners(ctx, tx); return err })
	return
}

// ReplaceAllowedOwners implements catalogue.Store.
func (a *Adapter) ReplaceAllowedOwners(ctx context.Context, owners []string, by string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.ReplaceAllowedOwners(ctx, tx, owners, by) })
}

// SeedAllowedOwners implements catalogue.Store.
func (a *Adapter) SeedAllowedOwners(ctx context.Context, owners []string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.SeedAllowedOwners(ctx, tx, owners) })
}

// ListSources implements catalogue.Store.
func (a *Adapter) ListSources(ctx context.Context) (out []store.CatalogueSource, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.ListSources(ctx, tx); return err })
	return
}

// AddSource implements catalogue.Store.
func (a *Adapter) AddSource(ctx context.Context, repo, by string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.AddSource(ctx, tx, repo, by) })
}

// RemoveSource implements catalogue.Store.
func (a *Adapter) RemoveSource(ctx context.Context, repo string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.RemoveSource(ctx, tx, repo) })
}

// SourceChecked implements catalogue.Store.
func (a *Adapter) SourceChecked(ctx context.Context, repo, module, errText string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.SourceChecked(ctx, tx, repo, module, errText, time.Now().UTC()) })
}

// InsertEntry implements catalogue.Store.
func (a *Adapter) InsertEntry(ctx context.Context, e store.CatalogueEntry) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.InsertEntry(ctx, tx, e) })
}

// LatestEntries implements catalogue.Store.
func (a *Adapter) LatestEntries(ctx context.Context) (out []store.CatalogueEntry, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.LatestEntries(ctx, tx); return err })
	return
}

// EntryBundle implements catalogue.Store.
func (a *Adapter) EntryBundle(ctx context.Context, module, version string) (out []byte, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.EntryBundle(ctx, tx, module, version); return err })
	return
}

// InsertJoin records a join bundle.
func (a *Adapter) InsertJoin(ctx context.Context, j store.CatalogueJoin) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error {
		if err := store.PruneJoins(ctx, tx, time.Now().UTC()); err != nil {
			return err
		}
		return store.InsertJoin(ctx, tx, j)
	})
}

// Entry returns one stored catalogue entry.
func (a *Adapter) Entry(ctx context.Context, module, version string) (out store.CatalogueEntry, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.GetEntry(ctx, tx, module, version); return err })
	return
}

// ClaimJoinRender counts one render of an agent join.
func (a *Adapter) ClaimJoinRender(ctx context.Context, id string) (out store.CatalogueJoin, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.ClaimJoinRender(ctx, tx, id, time.Now().UTC()); return err })
	return
}

// SetJoinJTI records the latest render's token.
func (a *Adapter) SetJoinJTI(ctx context.Context, id, jti string) error {
	return a.St.Tx(ctx, func(tx pgx.Tx) error { return store.SetJoinJTI(ctx, tx, id, jti) })
}

// GetJoin returns a join record.
func (a *Adapter) GetJoin(ctx context.Context, id string) (out store.CatalogueJoin, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error { out, err = store.GetJoin(ctx, tx, id, time.Now().UTC()); return err })
	return
}

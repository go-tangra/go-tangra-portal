// Package storeadapter binds the SQL store to the interfaces the registry and
// the operations API consume (memstore implements the same set for tests).
package storeadapter

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-freya/freya/services/gateway/internal/store"
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

// QueryAudit implements audit.Querier.
func (a *Adapter) QueryAudit(ctx context.Context, module, et string, from, to, cursor time.Time, limit int) (out []store.AuditRow, err error) {
	err = a.St.Tx(ctx, func(tx pgx.Tx) error {
		out, err = store.QueryAudit(ctx, tx, module, et, from, to, cursor, limit)
		return err
	})
	return
}

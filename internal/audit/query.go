package audit

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// Querier reads audit rows (store or memstore).
type Querier interface {
	QueryAudit(ctx context.Context, module, eventType string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error)
}

// Filter bounds an audit query.
type Filter struct {
	Module, EventType string
	From, To, Cursor  time.Time
	Limit             int
}

// MaxLimit caps page size.
const MaxLimit = 500

// Query validates the filter and reads a page.
func Query(ctx context.Context, q Querier, f Filter, now time.Time) ([]store.AuditRow, error) {
	if f.EventType != "" && !Known(f.EventType) {
		return nil, errors.New("audit: unknown event type")
	}
	if f.To.IsZero() {
		f.To = now
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-24 * time.Hour)
	}
	if f.From.After(f.To) {
		return nil, errors.New("audit: from after to")
	}
	if f.Limit <= 0 || f.Limit > MaxLimit {
		f.Limit = 100
	}
	return q.QueryAudit(ctx, f.Module, f.EventType, f.From, f.To, f.Cursor, f.Limit)
}

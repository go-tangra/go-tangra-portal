package audit

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/listquery"
)

// Querier reads audit rows (store or memstore).
type Querier interface {
	QueryAudit(ctx context.Context, module, eventType string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error)
	PageAudit(ctx context.Context, q store.AuditQuery, req listquery.Request) ([]store.AuditRow, int, listquery.Request, error)
}

// ErrFilter reports an invalid filter (unknown event type, from after to).
var ErrFilter = errors.New("audit: invalid filter")

// DefaultWindow bounds a page query without from/to so counts stay cheap on
// the hypertable (specs/032-server-side-tables research D6).
const DefaultWindow = 7 * 24 * time.Hour

// MaxAuditSpan caps to-from on every audit query: an explicit wide from (e.g.
// 1970) would otherwise force an exact count(*) and OFFSET over the whole
// hypertable on every page (specs/032 security review F-2).
const MaxAuditSpan = 90 * 24 * time.Hour

// ErrSpan reports a from/to range wider than MaxAuditSpan; handlers answer
// validation_failed naming the parameter "from".
var ErrSpan = errors.New("audit: from/to span exceeds the maximum")

// QueryPage validates the filter and reads one page of the list contract:
// events within [from, to] (default: the last DefaultWindow), counted and
// ordered per req.
func QueryPage(ctx context.Context, q Querier, f Filter, req listquery.Request, now time.Time) ([]store.AuditRow, int, listquery.Request, error) {
	if f.EventType != "" && !Known(f.EventType) {
		return nil, 0, req, ErrFilter
	}
	if f.To.IsZero() {
		f.To = now
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-DefaultWindow)
	}
	if f.From.After(f.To) {
		return nil, 0, req, ErrFilter
	}
	if f.To.Sub(f.From) > MaxAuditSpan {
		return nil, 0, req, ErrSpan
	}
	return q.PageAudit(ctx, store.AuditQuery{Module: f.Module, EventType: f.EventType, From: f.From, To: f.To}, req)
}

// Filter bounds an audit query.
type Filter struct {
	Module, EventType string
	From, To, Cursor  time.Time
	Limit             int
}

// MaxLimit caps page size.
const MaxLimit = 500

// Query validates the filter and reads a legacy cursor page: events within
// [from, to] (default: the last 24 hours), at most MaxAuditSpan wide.
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
	if f.To.Sub(f.From) > MaxAuditSpan {
		return nil, ErrSpan
	}
	if f.Limit <= 0 || f.Limit > MaxLimit {
		f.Limit = 100
	}
	return q.QueryAudit(ctx, f.Module, f.EventType, f.From, f.To, f.Cursor, f.Limit)
}

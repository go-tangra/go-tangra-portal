package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func conflict(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return err
}

// InsertAllow adds an allow-list entry.
func InsertAllow(ctx context.Context, tx pgx.Tx, e AllowEntry) error {
	_, err := tx.Exec(ctx, `INSERT INTO allow_list (id, spiffe_id, prefixes, names, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		e.ID, e.SpiffeID, e.Prefixes, e.Names, e.CreatedBy, e.CreatedAt)
	return conflict(err)
}

// AllowBySpiffeID returns the active entry for an identity.
func AllowBySpiffeID(ctx context.Context, tx pgx.Tx, id string) (AllowEntry, error) {
	var e AllowEntry
	err := tx.QueryRow(ctx, `SELECT id, spiffe_id, prefixes, names, created_by, created_at, revoked_at FROM allow_list WHERE spiffe_id = $1 AND revoked_at IS NULL`, id).
		Scan(&e.ID, &e.SpiffeID, &e.Prefixes, &e.Names, &e.CreatedBy, &e.CreatedAt, &e.RevokedAt)
	return e, notFound(err)
}

// ListAllow lists entries (active first).
func ListAllow(ctx context.Context, tx pgx.Tx) ([]AllowEntry, error) {
	rows, err := tx.Query(ctx, `SELECT id, spiffe_id, prefixes, names, created_by, created_at, revoked_at FROM allow_list ORDER BY revoked_at NULLS FIRST, spiffe_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AllowEntry
	for rows.Next() {
		var e AllowEntry
		if err := rows.Scan(&e.ID, &e.SpiffeID, &e.Prefixes, &e.Names, &e.CreatedBy, &e.CreatedAt, &e.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RevokeAllow retires an entry.
func RevokeAllow(ctx context.Context, tx pgx.Tx, id string, at time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE allow_list SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetMark records a mark, replacing any active mark on the module.
func SetMark(ctx context.Context, tx pgx.Tx, m Mark) error {
	if _, err := tx.Exec(ctx, `UPDATE module_marks SET cleared_at = $2 WHERE module = $1 AND cleared_at IS NULL`, m.Module, m.SetAt); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO module_marks (id, module, mark, reason, set_by, set_at) VALUES ($1,$2,$3,$4,$5,$6)`, m.ID, m.Module, m.Mark, m.Reason, m.SetBy, m.SetAt)
	return conflict(err)
}

// ClearMark clears the active mark of a module.
func ClearMark(ctx context.Context, tx pgx.Tx, module string, at time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE module_marks SET cleared_at = $2 WHERE module = $1 AND cleared_at IS NULL`, module, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ActiveMarks lists modules with an active mark.
func ActiveMarks(ctx context.Context, tx pgx.Tx) ([]Mark, error) {
	rows, err := tx.Query(ctx, `SELECT id, module, mark, reason, set_by, set_at, cleared_at FROM module_marks WHERE cleared_at IS NULL ORDER BY module`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Mark
	for rows.Next() {
		var m Mark
		if err := rows.Scan(&m.ID, &m.Module, &m.Mark, &m.Reason, &m.SetBy, &m.SetAt, &m.ClearedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// InsertAuditRows bulk-inserts audit rows.
func InsertAuditRows(ctx context.Context, tx pgx.Tx, rows []AuditRow) error {
	src := make([][]any, 0, len(rows))
	for _, r := range rows {
		src = append(src, []any{r.TS, r.EventType, r.Module, r.ActorKind, r.ActorID, r.TenantID, r.SubjectKind, r.SubjectID, r.Outcome, r.Reason, r.CorrelationID, r.Details})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"gateway_audit_events"}, []string{"ts", "event_type", "module", "actor_kind", "actor_id", "tenant_id",
		"subject_kind", "subject_id", "outcome", "reason", "correlation_id", "details"}, pgx.CopyFromRows(src))
	return err
}

// QueryAudit lists events with filters; cursor = ts of the last row seen.
func QueryAudit(ctx context.Context, tx pgx.Tx, module, eventType string, from, to, cursor time.Time, limit int) ([]AuditRow, error) {
	rows, err := tx.Query(ctx, `SELECT ts, event_type, module, actor_kind, actor_id, tenant_id, subject_kind, subject_id, outcome, reason, correlation_id, details
		FROM gateway_audit_events WHERE ($1 = '' OR module = $1) AND ($2 = '' OR event_type = $2) AND ts >= $3 AND ts <= $4
		AND ($5::timestamptz IS NULL OR ts < $5) ORDER BY ts DESC LIMIT $6`, module, eventType, from, to, nullTime(cursor), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.TS, &r.EventType, &r.Module, &r.ActorKind, &r.ActorID, &r.TenantID, &r.SubjectKind, &r.SubjectID, &r.Outcome, &r.Reason, &r.CorrelationID, &r.Details); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

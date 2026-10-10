package store

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
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

// SeeKnown records that a module is registered at m.LastSeenAt: it inserts
// the module or refreshes its identity, name, manifest and last-seen time. A
// newer version replaces last_version (empty never does); a forgotten module
// that registers again is known again. Repeating a call changes nothing.
func SeeKnown(ctx context.Context, tx pgx.Tx, m KnownModule) error {
	_, err := tx.Exec(ctx, `INSERT INTO known_modules (module, identity, display_name, last_version, manifest_hash, first_seen_at, last_seen_at)
VALUES ($1,$2,$3,$4,$5,$6,$6)
ON CONFLICT (module) DO UPDATE SET
  identity = EXCLUDED.identity,
  display_name = EXCLUDED.display_name,
  last_version = CASE WHEN EXCLUDED.last_version = '' THEN known_modules.last_version ELSE EXCLUDED.last_version END,
  manifest_hash = EXCLUDED.manifest_hash,
  last_seen_at = GREATEST(known_modules.last_seen_at, EXCLUDED.last_seen_at),
  forgotten_at = NULL`, m.Module, m.Identity, m.DisplayName, m.LastVersion, m.ManifestHash, m.LastSeenAt)
	return err
}

// ListKnown lists the modules not forgotten, by name.
func ListKnown(ctx context.Context, tx pgx.Tx) ([]KnownModule, error) {
	rows, err := tx.Query(ctx, `SELECT module, identity, display_name, last_version, manifest_hash, first_seen_at, last_seen_at, expected, forgotten_at
FROM known_modules WHERE forgotten_at IS NULL ORDER BY module`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KnownModule
	for rows.Next() {
		var m KnownModule
		if err := rows.Scan(&m.Module, &m.Identity, &m.DisplayName, &m.LastVersion, &m.ManifestHash, &m.FirstSeenAt, &m.LastSeenAt, &m.Expected, &m.ForgottenAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetKnownExpected sets whether a known module should be running.
func SetKnownExpected(ctx context.Context, tx pgx.Tx, module string, expected bool) error {
	tag, err := tx.Exec(ctx, `UPDATE known_modules SET expected = $2 WHERE module = $1 AND forgotten_at IS NULL`, module, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ForgetKnown removes a module from the known list (it reappears if it
// registers again).
func ForgetKnown(ctx context.Context, tx pgx.Tx, module string, at time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE known_modules SET forgotten_at = $2 WHERE module = $1 AND forgotten_at IS NULL`, module, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAllowedOwners lists the catalogue's allowed GitHub owners.
func ListAllowedOwners(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT owner FROM catalogue_allowed_owners ORDER BY owner`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ReplaceAllowedOwners sets the allowed owners.
func ReplaceAllowedOwners(ctx context.Context, tx pgx.Tx, owners []string, by string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM catalogue_allowed_owners WHERE NOT (owner = ANY($1))`, owners); err != nil {
		return err
	}
	for _, o := range owners {
		if _, err := tx.Exec(ctx, `INSERT INTO catalogue_allowed_owners (owner, added_by) VALUES ($1,$2) ON CONFLICT (owner) DO NOTHING`, o, by); err != nil {
			return err
		}
	}
	return nil
}

// SeedAllowedOwners inserts owners when the list is empty (first start).
func SeedAllowedOwners(ctx context.Context, tx pgx.Tx, owners []string) error {
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM catalogue_allowed_owners`).Scan(&n); err != nil || n > 0 {
		return err
	}
	return ReplaceAllowedOwners(ctx, tx, owners, "config")
}

// ListSources lists catalogue sources by repository.
func ListSources(ctx context.Context, tx pgx.Tx) ([]CatalogueSource, error) {
	rows, err := tx.Query(ctx, `SELECT repo, added_by, coalesce(module, ''), last_error, added_at, last_checked_at FROM catalogue_sources ORDER BY repo`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CatalogueSource{}
	for rows.Next() {
		var c CatalogueSource
		if err := rows.Scan(&c.Repo, &c.AddedBy, &c.Module, &c.LastError, &c.AddedAt, &c.LastCheckedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddSource adds a repository (ErrConflict when present).
func AddSource(ctx context.Context, tx pgx.Tx, repo, by string) error {
	_, err := tx.Exec(ctx, `INSERT INTO catalogue_sources (repo, added_by) VALUES ($1,$2)`, repo, by)
	return conflict(err)
}

// RemoveSource removes a repository; its entries stay.
func RemoveSource(ctx context.Context, tx pgx.Tx, repo string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM catalogue_sources WHERE lower(repo) = lower($1)`, repo)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SourceChecked records a check of a source: its error text ("" = ok) and,
// once known, the module it publishes (ErrConflict when another source
// already publishes that module).
func SourceChecked(ctx context.Context, tx pgx.Tx, repo, module, errText string, at time.Time) error {
	var mod any
	if module != "" {
		mod = module
	}
	_, err := tx.Exec(ctx, `UPDATE catalogue_sources SET last_checked_at = $2, last_error = $3, module = coalesce($4, module) WHERE lower(repo) = lower($1)`, repo, at, errText, mod)
	return conflict(err)
}

// InsertEntry stores a verified entry (ErrConflict when that version exists).
func InsertEntry(ctx context.Context, tx pgx.Tx, e CatalogueEntry) error {
	_, err := tx.Exec(ctx, `INSERT INTO catalogue_entries (module, version, repo, version_key, entry, entry_sha256, bundle, bundle_sha256, attested_by, verified_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, e.Module, e.Version, e.Repo, e.VersionKey, e.Entry, e.EntrySHA256, e.Bundle, e.BundleSHA256, e.AttestedBy, e.VerifiedAt)
	return conflict(err)
}

// LatestEntries returns the newest entry per module, without bundles.
func LatestEntries(ctx context.Context, tx pgx.Tx) ([]CatalogueEntry, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (module) module, version, repo, version_key, entry, entry_sha256, bundle_sha256, attested_by, verified_at
FROM catalogue_entries ORDER BY module, version_key DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CatalogueEntry{}
	for rows.Next() {
		var e CatalogueEntry
		if err := rows.Scan(&e.Module, &e.Version, &e.Repo, &e.VersionKey, &e.Entry, &e.EntrySHA256, &e.BundleSHA256, &e.AttestedBy, &e.VerifiedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EntryBundle returns the bundle of one stored entry.
func EntryBundle(ctx context.Context, tx pgx.Tx, module, version string) ([]byte, error) {
	var b []byte
	if err := tx.QueryRow(ctx, `SELECT bundle FROM catalogue_entries WHERE module = $1 AND version = $2`, module, version).Scan(&b); err != nil {
		return nil, notFound(err)
	}
	return b, nil
}

// InsertJoin records a join bundle.
func InsertJoin(ctx context.Context, tx pgx.Tx, j CatalogueJoin) error {
	_, err := tx.Exec(ctx, `INSERT INTO catalogue_joins (id, module, version, jti, minted_by, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		j.ID, j.Module, j.Version, j.JTI, j.MintedBy, j.CreatedAt, j.ExpiresAt)
	return conflict(err)
}

// GetJoin returns a join record kept for progress (24 h past expiry).
func GetJoin(ctx context.Context, tx pgx.Tx, id string, now time.Time) (CatalogueJoin, error) {
	var j CatalogueJoin
	err := tx.QueryRow(ctx, `SELECT id::text, module, version, jti::text, minted_by, created_at, expires_at FROM catalogue_joins
WHERE id = $1 AND expires_at > $2`, id, now.Add(-24*time.Hour)).Scan(&j.ID, &j.Module, &j.Version, &j.JTI, &j.MintedBy, &j.CreatedAt, &j.ExpiresAt)
	return j, notFound(err)
}

// PruneJoins deletes join records 24 h past expiry.
func PruneJoins(ctx context.Context, tx pgx.Tx, now time.Time) error {
	_, err := tx.Exec(ctx, `DELETE FROM catalogue_joins WHERE expires_at <= $1`, now.Add(-24*time.Hour))
	return err
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

// PageAudit counts the events matching q, clamps req to the last page and
// reads that page in req's order (store.AuditList), in one transaction.
func PageAudit(ctx context.Context, tx pgx.Tx, q AuditQuery, req listquery.Request) ([]AuditRow, int, listquery.Request, error) {
	const where = `FROM gateway_audit_events WHERE ($1 = '' OR module = $1) AND ($2 = '' OR event_type = $2) AND ts >= $3 AND ts <= $4`
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) `+where, q.Module, q.EventType, q.From, q.To).Scan(&total); err != nil {
		return nil, 0, req, err
	}
	req = req.Clamp(total)
	rows, err := tx.Query(ctx, `SELECT id, ts, event_type, module, actor_kind, actor_id, tenant_id, subject_kind, subject_id, outcome, reason, correlation_id, details `+
		where+` ORDER BY `+req.OrderBy(AuditList)+` LIMIT $5 OFFSET $6`, q.Module, q.EventType, q.From, q.To, req.Limit(), req.Offset())
	if err != nil {
		return nil, 0, req, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.TS, &r.EventType, &r.Module, &r.ActorKind, &r.ActorID, &r.TenantID, &r.SubjectKind, &r.SubjectID, &r.Outcome, &r.Reason, &r.CorrelationID, &r.Details); err != nil {
			return nil, 0, req, err
		}
		out = append(out, r)
	}
	return out, total, req, rows.Err()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

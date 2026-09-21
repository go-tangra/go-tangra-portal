// Package store is the TimescaleDB persistence layer for the gateway's durable
// state: the registrant allow-list, operator marks and the audit log.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store wraps the connection pool.
type Store struct{ pool *pgxpool.Pool }

// Open connects with the application DSN.
func Open(ctx context.Context, dsn string, maxConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Migrate applies the embedded migrations under an advisory lock.
func Migrate(ctx context.Context, dsn string) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_lock(7241003)"); err != nil {
		return fmt.Errorf("store: migrate lock: %w", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, "SELECT pg_advisory_unlock(7241003)") }()
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// Tx runs fn in a transaction.
func (s *Store) Tx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ErrNotFound is returned for missing rows.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a unique constraint refuses an insert.
var ErrConflict = errors.New("store: conflict")

// Now is the clock used for timestamps (overridable in tests).
var Now = time.Now

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// InsertAuditRows writes an audit batch (audit.Inserter).
func (s *Store) InsertAuditRows(ctx context.Context, rows []AuditRow) error {
	return s.Tx(ctx, func(tx pgx.Tx) error { return InsertAuditRows(ctx, tx, rows) })
}

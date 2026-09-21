package store

import "time"

// AllowEntry is one allow-list row.
type AllowEntry struct {
	ID, SpiffeID string
	Prefixes     []string
	Names        []string
	CreatedBy    string
	CreatedAt    time.Time
	RevokedAt    *time.Time
}

// Mark is an operator mark on a module.
type Mark struct {
	ID, Module, Mark, Reason, SetBy string
	SetAt                           time.Time
	ClearedAt                       *time.Time
}

// AuditRow is one gateway audit event.
type AuditRow struct {
	TS            time.Time
	EventType     string
	Module        string
	ActorKind     string
	ActorID       string
	TenantID      *string
	SubjectKind   string
	SubjectID     string
	Outcome       string
	Reason        string
	CorrelationID string
	Details       []byte
}

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

// KnownModule is a module the gateway has seen register.
type KnownModule struct {
	Module, Identity, DisplayName string
	LastVersion, ManifestHash     string
	FirstSeenAt, LastSeenAt       time.Time
	Expected                      bool
	ForgottenAt                   *time.Time
}

// AuditRow is one gateway audit event.
type AuditRow struct {
	ID            int64
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

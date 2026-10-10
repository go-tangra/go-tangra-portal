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

// CatalogueSource is a GitHub repository the catalogue reads.
type CatalogueSource struct {
	Repo, AddedBy, Module, LastError string
	AddedAt                          time.Time
	LastCheckedAt                    *time.Time
}

// CatalogueEntry is a verified release entry. Bundle is only loaded by
// EntryBundle (listing never reads it).
type CatalogueEntry struct {
	Module, Version, Repo     string
	VersionKey                int64
	Entry                     []byte
	EntrySHA256, BundleSHA256 string
	Bundle                    []byte
	AttestedBy                string
	VerifiedAt                time.Time
}

// CatalogueJoin is one join bundle made by the add-module wizard.
type CatalogueJoin struct {
	ID, Module, Version, JTI, MintedBy string
	CreatedAt, ExpiresAt               time.Time
	// Channel is JoinDownload or JoinAgent (spec 037). Agent joins keep the
	// tenant, host and host inputs and are rendered when the agent fetches,
	// at most MaxJoinRenders times; JTI is the latest render's token.
	Channel          string
	TenantID, HostID string
	Inputs           map[string]string
	Renders          int
}

// Join channels.
const (
	JoinDownload = "download"
	JoinAgent    = "agent"
)

// MaxJoinRenders bounds how often an agent join is rendered.
const MaxJoinRenders = 5

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

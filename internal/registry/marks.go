package registry

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/go-freya/freya/services/gateway/internal/audit"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

// MarkWriter persists operator marks; AllowAdmin manages the allow-list.
type MarkWriter interface {
	SetMark(ctx context.Context, m store.Mark) error
	ClearMark(ctx context.Context, module string) error
}

// AllowAdmin manages allow-list entries.
type AllowAdmin interface {
	InsertAllow(ctx context.Context, e store.AllowEntry) error
	ListAllow(ctx context.Context) ([]store.AllowEntry, error)
	RevokeAllow(ctx context.Context, id string) error
}

// Operator identifies who performs an operation (audited).
type Operator struct {
	UserID   string
	TenantID string
}

// Errors of the operations service.
var (
	ErrUnknownModule = errors.New("registry: unknown module")
	ErrReason        = errors.New("registry: a reason of at least 10 characters is required")
	ErrAllowEntry    = errors.New("registry: invalid allow-list entry")
)

// Ops applies operator controls: drain, undrain, revoke and the allow-list.
type Ops struct {
	Reg   *Registry
	Marks MarkWriter
	Allow AllowAdmin
	Audit *audit.Writer
	Now   func() time.Time
}

// Drain marks a module: new requests are refused (503) while in-flight ones
// complete; renewals are refused so instances withdraw.
func (o *Ops) Drain(ctx context.Context, module string, by Operator) error {
	if _, ok := o.Reg.Get(module); !ok {
		return ErrUnknownModule
	}
	if err := o.Marks.SetMark(ctx, store.Mark{ID: uuid.Must(uuid.NewV7()).String(), Module: module, Mark: "draining", SetBy: by.UserID, SetAt: o.now()}); err != nil {
		return err
	}
	o.Reg.ApplyMark(ctx, module, "draining")
	o.emit(audit.Event{Type: audit.ModuleDrained, Module: module, ActorKind: "operator", ActorID: by.UserID, TenantID: by.TenantID, Outcome: "ok", Reason: "drained", SubjectKind: "module", SubjectID: module})
	return nil
}

// Undrain clears a draining mark (revoked modules stay revoked).
func (o *Ops) Undrain(ctx context.Context, module string, by Operator) error {
	if o.Reg.State(module) != StateDraining {
		return ErrUnknownModule
	}
	if err := o.Marks.ClearMark(ctx, module); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	o.Reg.ApplyMark(ctx, module, "")
	o.emit(audit.Event{Type: audit.ModuleRecovered, Module: module, ActorKind: "operator", ActorID: by.UserID, TenantID: by.TenantID, Outcome: "ok", Reason: "undrained", SubjectKind: "module", SubjectID: module})
	return nil
}

// Revoke withdraws a module durably: routes disappear, renewals and new
// registrations are refused until the mark is cleared.
func (o *Ops) Revoke(ctx context.Context, module, reason string, by Operator) error {
	if len(strings.TrimSpace(reason)) < 10 || len(reason) > 500 {
		return ErrReason
	}
	if _, ok := o.Reg.Get(module); !ok && o.Reg.State(module) == "" {
		return ErrUnknownModule
	}
	if err := o.Marks.SetMark(ctx, store.Mark{ID: uuid.Must(uuid.NewV7()).String(), Module: module, Mark: "revoked", Reason: reason, SetBy: by.UserID, SetAt: o.now()}); err != nil {
		return err
	}
	o.Reg.ApplyMark(ctx, module, "revoked")
	o.emit(audit.Event{Type: audit.ModuleRevoked, Module: module, ActorKind: "operator", ActorID: by.UserID, TenantID: by.TenantID, Outcome: "ok", Reason: "revoked", SubjectKind: "module", SubjectID: module, Details: map[string]any{"reason": reason}})
	return nil
}

// AddAllow adds an allow-list entry (prefixes normalised, names validated).
func (o *Ops) AddAllow(ctx context.Context, e store.AllowEntry, by Operator) (store.AllowEntry, error) {
	if !strings.HasPrefix(e.SpiffeID, "spiffe://") || len(e.Prefixes) == 0 || len(e.Names) == 0 || len(e.Prefixes) > 32 || len(e.Names) > 32 {
		return store.AllowEntry{}, ErrAllowEntry
	}
	for i, p := range e.Prefixes {
		n, ok := normalizePrefix(p)
		if !ok {
			return store.AllowEntry{}, ErrAllowEntry
		}
		e.Prefixes[i] = n
	}
	for _, n := range e.Names {
		if !moduleNameOK(n) {
			return store.AllowEntry{}, ErrAllowEntry
		}
	}
	e.ID = uuid.Must(uuid.NewV7()).String()
	e.CreatedBy = by.UserID
	e.CreatedAt = o.now()
	if err := o.Allow.InsertAllow(ctx, e); err != nil {
		return store.AllowEntry{}, err
	}
	o.emit(audit.Event{Type: audit.AllowlistChanged, ActorKind: "operator", ActorID: by.UserID, TenantID: by.TenantID, Outcome: "ok", Reason: "added", SubjectKind: "allow_entry", SubjectID: e.ID,
		Details: map[string]any{"spiffe_id": e.SpiffeID, "prefixes": e.Prefixes, "names": e.Names}})
	return e, nil
}

// RevokeAllow retires an entry; running registrations are unaffected until
// they re-register.
func (o *Ops) RevokeAllow(ctx context.Context, id string, by Operator) error {
	if err := o.Allow.RevokeAllow(ctx, id); err != nil {
		return err
	}
	o.emit(audit.Event{Type: audit.AllowlistChanged, ActorKind: "operator", ActorID: by.UserID, TenantID: by.TenantID, Outcome: "ok", Reason: "revoked", SubjectKind: "allow_entry", SubjectID: id})
	return nil
}

// ListAllow lists entries.
func (o *Ops) ListAllow(ctx context.Context) ([]store.AllowEntry, error) {
	return o.Allow.ListAllow(ctx)
}

func (o *Ops) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}

func (o *Ops) emit(e audit.Event) {
	if o.Audit != nil {
		_ = o.Audit.Emit(e)
	}
}

func moduleNameOK(n string) bool {
	if len(n) < 2 || len(n) > 40 || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func normalizePrefix(p string) (string, bool) {
	if p == "" || p[0] != '/' || len(p) > 128 || strings.ContainsAny(p, "%?#\\ \t\r\n") {
		return "", false
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, "{") {
			return "", false
		}
	}
	return p, true
}

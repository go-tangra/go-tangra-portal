// Package authz decides API permissions for a resolved identity through
// auth.v1.Authorization/BatchCheck, with a short decision cache keyed by the
// tenant's policy version. Outages deny (fail closed) and are audited.
package authz

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
)

// Checker is auth.v1.AuthorizationClient's BatchCheck.
type Checker interface {
	BatchCheck(ctx context.Context, in *authv1.BatchCheckRequest, opts ...grpc.CallOption) (*authv1.BatchCheckResponse, error)
}

// KV caches decisions.
type KV interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
}

// ErrUnavailable means no decision could be obtained (the call is denied).
var ErrUnavailable = errors.New("authz: decisions unavailable")

// Options configure the decider.
type Options struct {
	Client Checker
	KV     KV
	Audit  *audit.Writer
	TTL    time.Duration // default 2s
}

// Decider answers permission questions.
type Decider struct {
	o        Options
	mu       sync.RWMutex
	versions map[string]string // tenant → policy version last seen
}

// New builds a decider.
func New(o Options) (*Decider, error) {
	if o.Client == nil || o.KV == nil {
		return nil, errors.New("authz: client and kv are required")
	}
	if o.TTL <= 0 {
		o.TTL = 2 * time.Second
	}
	return &Decider{o: o, versions: map[string]string{}}, nil
}

// Decision is one answer.
type Decision struct {
	Allowed bool
	Reason  string
	Version string
}

// TenantVersion is the policy version last observed for a tenant ("" unknown).
func (d *Decider) TenantVersion(tenant string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.versions[tenant]
}

// Ref names a permission of one module: Perm is the bare "resource:action"
// the module declares in its manifest, Module the registration that owns it.
// The same Perm of two modules are different permissions.
type Ref struct {
	Module string
	Perm   string
}

// String renders the ref as "module:resource:action".
func (r Ref) String() string { return r.Module + ":" + r.Perm }

// Check decides a list of module permissions for a user; cached answers are
// used when present, the rest are asked in one BatchCheck (refs may mix
// modules). Invalid refs are refused as unknown_permission without asking.
func (d *Decider) Check(ctx context.Context, tenant, user string, refs []Ref) ([]Decision, error) {
	out := make([]Decision, len(refs))
	version := d.TenantVersion(tenant)
	var missing []int
	for i, r := range refs {
		if !validRef(r) {
			out[i] = Decision{Reason: "unknown_permission"}
			continue
		}
		if version != "" {
			if raw, ok, err := d.o.KV.Get(ctx, key(tenant, user, r, version)); err == nil && ok {
				out[i] = Decision{Allowed: strings.HasPrefix(raw, "1:"), Reason: strings.TrimPrefix(strings.TrimPrefix(raw, "1:"), "0:"), Version: version}
				continue
			}
		}
		missing = append(missing, i)
	}
	if len(missing) == 0 {
		return out, nil
	}
	req := &authv1.BatchCheckRequest{TenantId: tenant, UserId: user}
	for _, i := range missing {
		res, act, _ := strings.Cut(refs[i].Perm, ":")
		req.Permissions = append(req.Permissions, &authv1.PermissionRef{Module: refs[i].Module, Resource: res, Action: act})
	}
	resp, err := d.o.Client.BatchCheck(ctx, req)
	if err != nil || len(resp.GetResults()) != len(missing) {
		return nil, ErrUnavailable
	}
	for j, i := range missing {
		r := resp.Results[j]
		out[i] = Decision{Allowed: r.GetAllowed(), Reason: r.GetReason(), Version: r.GetPolicyVersion()}
		if v := r.GetPolicyVersion(); v != "" {
			d.mu.Lock()
			d.versions[tenant] = v
			d.mu.Unlock()
			mark := "0:"
			if r.GetAllowed() {
				mark = "1:"
			}
			_ = d.o.KV.Set(ctx, key(tenant, user, refs[i], v), mark+r.GetReason(), d.o.TTL)
		}
	}
	return out, nil
}

// Allowed decides one permission of module (the route's module) and audits
// refusals (permission_refused).
func (d *Decider) Allowed(ctx context.Context, module, tenant, user, perm string) (bool, error) {
	ds, err := d.Check(ctx, tenant, user, []Ref{{Module: module, Perm: perm}})
	if err != nil {
		d.emit(audit.Event{Type: audit.PermissionRefused, Module: module, ActorKind: "user", ActorID: user, TenantID: tenant, Outcome: "failed", Reason: "decision_unavailable", Details: map[string]any{"permission": perm}})
		return false, err
	}
	if !ds[0].Allowed {
		reason := ds[0].Reason
		if reason == "" {
			reason = "no_permission"
		}
		d.emit(audit.Event{Type: audit.PermissionRefused, Module: module, ActorKind: "user", ActorID: user, TenantID: tenant, Outcome: "refused", Reason: reason, Details: map[string]any{"permission": perm}})
		return false, nil
	}
	return true, nil
}

func (d *Decider) emit(e audit.Event) {
	if d.o.Audit != nil {
		_ = d.o.Audit.Emit(e)
	}
}

// key namespaces the gateway's decision cache. It must not share a namespace
// with the auth service's own decision cache (auth encodes values as "0" or a
// reason string; the gateway encodes "0:"/"1:"+reason): a shared Valkey would
// otherwise let one service read the other's values and mis-decide. The
// module is part of the key: one module's answer never decides another's.
func key(tenant, user string, r Ref, version string) string {
	return "gwdec:" + tenant + ":" + user + ":" + r.Module + ":" + r.Perm + "@" + version
}

var (
	// moduleRE is the manifest's module grammar.
	moduleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	// permRE is the manifest's bare "resource:action" grammar.
	permRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$`)
)

// validRef accepts a bare manifest permission of a named module. A missing
// module is refused: auth would evaluate the legacy, unscoped permission.
func validRef(r Ref) bool {
	return moduleRE.MatchString(r.Module) && permRE.MatchString(r.Perm)
}

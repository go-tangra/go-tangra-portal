// Package registry holds module registrations: manifests, instances and
// leases (Valkey with an in-memory mirror), the allow-list check, conflict
// detection, operator marks, health state and the immutable route snapshot
// every request is dispatched against.
package registry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
	"github.com/go-tangra/go-tangra-portal/v4/internal/route"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// Error is a refusal with a gRPC code and a closed-vocabulary reason.
type Error struct {
	Code   codes.Code
	Reason string
}

func (e *Error) Error() string { return e.Reason }

// Refusal reasons.
const (
	ReasonIdentityNotAllowed = "identity_not_allowed"
	ReasonNameNotGranted     = "name_not_granted"
	ReasonPrefixNotGranted   = "prefix_not_granted"
	ReasonPrefixConflict     = "prefix_conflict"
	ReasonIdentityMismatch   = "identity_mismatch"
	ReasonManifestDrift      = "manifest_drift"
	ReasonManifestInvalid    = "manifest_invalid"
	ReasonSubjectConflict    = "subject_conflict"
	ReasonModuleRevoked      = "module_revoked"
	ReasonModuleDraining     = "module_draining"
	ReasonUnknownLease       = "unknown_lease"
	ReasonBackendRequired    = "backend_required"
	ReasonUnavailable        = "registry_unavailable"
)

// Backend is where a module instance is reached.
type Backend struct {
	HTTPURL    string `json:"http_url,omitempty"`
	GRPCTarget string `json:"grpc_target,omitempty"`
}

// Instance is one registered process of a module.
type Instance struct {
	ID           string    `json:"id"`
	Backend      Backend   `json:"backend"`
	LeaseID      string    `json:"lease_id"`
	ManifestHash string    `json:"manifest_hash"`
	RegisteredAt time.Time `json:"registered_at"`
	RenewedAt    time.Time `json:"renewed_at"`
}

// Registration is a module with its manifest and instances.
type Registration struct {
	Module       string               `json:"module"`
	Identity     string               `json:"identity"`
	Manifest     manifest.Manifest    `json:"manifest"`
	Hash         string               `json:"hash"`
	Instances    map[string]Instance  `json:"instances"`
	RegisteredAt time.Time            `json:"registered_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
	Unhealthy    map[string]time.Time `json:"-"` // instance → since (local health view)
}

// State derives the module state from marks and health.
type State string

// Module states.
const (
	StateActive    State = "active"
	StateDraining  State = "draining"
	StateUnhealthy State = "unhealthy"
	StateRevoked   State = "revoked"
)

// Event is a registry change (also the wire form on the pub/sub channel).
type Event struct {
	TS      time.Time `json:"ts"`
	Kind    string    `json:"kind"`
	Module  string    `json:"module"`
	Version uint64    `json:"version"`
	Origin  string    `json:"origin,omitempty"` // gateway instance that produced it
}

// Lease is what a registrant holds.
type Lease struct {
	ID       string
	Module   string
	Instance string
	TTL      time.Duration
	Renew    time.Duration
	Version  uint64
}

// AllowStore looks up the allow-list; MarkStore lists operator marks.
type AllowStore interface {
	AllowBySpiffeID(ctx context.Context, id string) (store.AllowEntry, error)
}

// MarkStore lists active operator marks.
type MarkStore interface {
	ActiveMarks(ctx context.Context) ([]store.Mark, error)
}

// Options configure the registry.
type Options struct {
	KV     KV
	Allow  AllowStore
	Marks  MarkStore
	Audit  *audit.Writer
	TTL    time.Duration
	Renew  time.Duration
	Now    func() time.Time
	Logger *slog.Logger
	// Origin identifies this gateway instance on the pub/sub channel.
	Origin string
	// Sweep is how often expired leases are collected (default Renew/2).
	Sweep time.Duration
	// OnAccepted is called after a registration or manifest update is
	// recorded (e.g. to register the module's permissions with auth).
	OnAccepted func(ctx context.Context, m manifest.Manifest)
}

// Registry is safe for concurrent use.
type Registry struct {
	o       Options
	mu      sync.RWMutex
	regs    map[string]*Registration
	leases  map[string]leaseRef // lease id → module/instance (local mirror)
	marks   map[string]string   // module → draining|revoked
	version atomic.Uint64
	table   atomic.Pointer[route.Table]
	events  []Event // ring of recent events for Watch replay
	wmu     sync.Mutex
	watch   map[int]chan Event
	nextW   int
}

type leaseRef struct{ module, instance string }

const eventRing = 512

// New builds a registry and loads the current state from the KV.
func New(o Options) (*Registry, error) {
	if o.KV == nil || o.Allow == nil {
		return nil, errors.New("registry: kv and allow store are required")
	}
	if o.TTL <= 0 {
		o.TTL = 30 * time.Second
	}
	if o.Renew <= 0 {
		o.Renew = 10 * time.Second
	}
	if o.Sweep <= 0 {
		o.Sweep = o.Renew / 2
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Origin == "" {
		o.Origin = newID()
	}
	r := &Registry{o: o, regs: map[string]*Registration{}, leases: map[string]leaseRef{}, marks: map[string]string{}, watch: map[int]chan Event{}}
	r.table.Store(route.Empty())
	return r, nil
}

// Load reads marks and every registration from the KV (start-up and
// after a pub/sub notification from another instance).
func (r *Registry) Load(ctx context.Context) error {
	if err := r.RefreshMarks(ctx); err != nil {
		return err
	}
	keys, err := r.o.KV.Keys(ctx, regPrefix)
	if err != nil {
		return fmt.Errorf("registry: load: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range keys {
		if k == versionKey {
			continue
		}
		if err := r.reloadLocked(ctx, strings.TrimPrefix(k, regPrefix)); err != nil {
			return err
		}
	}
	if v, ok, err := r.o.KV.Get(ctx, versionKey); err == nil && ok {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			r.version.Store(n)
		}
	}
	r.rebuildLocked()
	return nil
}

// reloadLocked replaces the local copy of a module from the KV.
func (r *Registry) reloadLocked(ctx context.Context, module string) error {
	raw, ok, err := r.o.KV.Get(ctx, regKey(module))
	if err != nil {
		return fmt.Errorf("registry: reload %s: %w", module, err)
	}
	if !ok {
		r.forgetLocked(module)
		return nil
	}
	var reg Registration
	if err := json.Unmarshal([]byte(raw), &reg); err != nil {
		return fmt.Errorf("registry: reload %s: %w", module, err)
	}
	if reg.Instances == nil {
		reg.Instances = map[string]Instance{}
	}
	if old := r.regs[module]; old != nil {
		reg.Unhealthy = old.Unhealthy
	}
	for id := range r.leases {
		if r.leases[id].module == module {
			r.leases = without(r.leases, id)
		}
	}
	for _, in := range reg.Instances {
		r.leases[in.LeaseID] = leaseRef{module, in.ID}
	}
	r.regs[module] = &reg
	return nil
}

func without(m map[string]leaseRef, id string) map[string]leaseRef {
	next := make(map[string]leaseRef, len(m))
	for k, v := range m {
		if k != id {
			next[k] = v
		}
	}
	return next
}

func (r *Registry) forgetLocked(module string) {
	next := make(map[string]*Registration, len(r.regs))
	for k, v := range r.regs {
		if k != module {
			next[k] = v
		}
	}
	r.regs = next
	for id, ref := range r.leases {
		if ref.module == module {
			r.leases = without(r.leases, id)
		}
	}
}

// RefreshMarks reloads operator marks from the store.
func (r *Registry) RefreshMarks(ctx context.Context) error {
	if r.o.Marks == nil {
		return nil
	}
	marks, err := r.o.Marks.ActiveMarks(ctx)
	if err != nil {
		return fmt.Errorf("registry: marks: %w", err)
	}
	next := map[string]string{}
	for _, m := range marks {
		next[m.Module] = m.Mark
	}
	r.mu.Lock()
	r.marks = next
	r.rebuildLocked()
	r.mu.Unlock()
	return nil
}

// ApplyMark records an operator mark locally ("" clears it), rebuilds the
// snapshot and announces the change; the durable row is written by the caller.
func (r *Registry) ApplyMark(ctx context.Context, module, mark string) {
	r.mu.Lock()
	next := map[string]string{}
	for k, v := range r.marks {
		if k != module {
			next[k] = v
		}
	}
	if mark != "" {
		next[module] = mark
	}
	r.marks = next
	r.rebuildLocked()
	r.mu.Unlock()
	kind := EventRecovered
	switch mark {
	case "draining":
		kind = EventDrained
	case "revoked":
		kind = EventRevoked
	}
	r.announce(ctx, kind, module)
}

// Version is the registry version (monotonic across changes).
func (r *Registry) Version() uint64 { return r.version.Load() }

// Table is the current immutable route snapshot.
func (r *Registry) Table() *route.Table { return r.table.Load() }

// Get returns a copy of a registration.
func (r *Registry) Get(module string) (Registration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.regs[module]
	if !ok {
		return Registration{}, false
	}
	return copyReg(reg), true
}

// Registrations lists copies of every registration, sorted by module.
func (r *Registry) Registrations() []Registration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Registration, 0, len(r.regs))
	for _, reg := range r.regs {
		out = append(out, copyReg(reg))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out
}

func copyReg(reg *Registration) Registration {
	c := *reg
	c.Instances = make(map[string]Instance, len(reg.Instances))
	for k, v := range reg.Instances {
		c.Instances[k] = v
	}
	c.Unhealthy = make(map[string]time.Time, len(reg.Unhealthy))
	for k, v := range reg.Unhealthy {
		c.Unhealthy[k] = v
	}
	return c
}

// State returns the module state ("" when unknown).
func (r *Registry) State(module string) State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.regs[module]
	if !ok {
		return ""
	}
	return r.stateLocked(reg)
}

func (r *Registry) stateLocked(reg *Registration) State {
	switch r.marks[reg.Module] {
	case "revoked":
		return StateRevoked
	case "draining":
		return StateDraining
	}
	if len(reg.Instances) > 0 && len(reg.Unhealthy) >= len(reg.Instances) {
		return StateUnhealthy
	}
	return StateActive
}

// Backends lists the healthy instances of a module (all of them when every
// instance is unhealthy, so a recovery probe can succeed through traffic).
func (r *Registry) Backends(module string) (identity string, out []Instance) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.regs[module]
	if !ok {
		return "", nil
	}
	for id, in := range reg.Instances {
		if _, bad := reg.Unhealthy[id]; !bad {
			out = append(out, in)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return reg.Identity, out
}

// SetHealth records an instance's health; module-level flips are announced
// and audited (module_unhealthy / module_recovered).
func (r *Registry) SetHealth(ctx context.Context, module, instance string, healthy bool) {
	r.mu.Lock()
	reg, ok := r.regs[module]
	if !ok {
		r.mu.Unlock()
		return
	}
	if _, known := reg.Instances[instance]; !known {
		r.mu.Unlock()
		return
	}
	before := r.stateLocked(reg)
	if reg.Unhealthy == nil {
		reg.Unhealthy = map[string]time.Time{}
	}
	_, was := reg.Unhealthy[instance]
	if healthy && was {
		next := map[string]time.Time{}
		for k, v := range reg.Unhealthy {
			if k != instance {
				next[k] = v
			}
		}
		reg.Unhealthy = next
	} else if !healthy && !was {
		reg.Unhealthy[instance] = r.o.Now()
	}
	after := r.stateLocked(reg)
	r.rebuildLocked()
	r.mu.Unlock()
	if before == after {
		return
	}
	switch after {
	case StateUnhealthy:
		r.emit(audit.Event{Type: audit.ModuleUnhealthy, Module: module, ActorKind: "system", Outcome: "failed", Reason: "probes_failed", SubjectKind: "instance", SubjectID: instance})
		r.announce(ctx, EventUnhealthy, module)
	case StateActive:
		if before == StateUnhealthy {
			r.emit(audit.Event{Type: audit.ModuleRecovered, Module: module, ActorKind: "system", Outcome: "ok", Reason: "probe_ok", SubjectKind: "instance", SubjectID: instance})
			r.announce(ctx, EventRecovered, module)
		}
	}
}

// rebuildLocked recomputes the route snapshot from the local mirror.
func (r *Registry) rebuildLocked() {
	mods := make([]route.Module, 0, len(r.regs))
	for _, reg := range r.regs {
		st := r.stateLocked(reg)
		if st == StateRevoked || len(reg.Instances) == 0 {
			continue
		}
		mods = append(mods, route.Module{Name: reg.Module, State: string(st), Manifest: reg.Manifest})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Name < mods[j].Name })
	t, err := route.Build(mods)
	if err != nil {
		// Cannot happen: overlap is refused at registration. Keep the last good table.
		r.o.Logger.Error("route table rebuild failed", "err", err)
		return
	}
	r.table.Store(t)
}

// Register validates and records an instance; identity is the verified peer.
func (r *Registry) Register(ctx context.Context, identity string, req *gatewayv1.RegisterRequest) (Lease, error) {
	m, err := manifest.FromProto(req.GetManifest())
	if err != nil {
		return r.refuse(identity, "", &Error{codes.InvalidArgument, ReasonManifestInvalid}, map[string]any{"error": err.Error()})
	}
	be := Backend{HTTPURL: req.GetBackend().GetHttpUrl(), GRPCTarget: req.GetBackend().GetGrpcTarget()}
	if (len(m.Routes) > 0 && !strings.HasPrefix(be.HTTPURL, "https://")) || (len(m.Methods) > 0 && be.GRPCTarget == "") {
		return r.refuse(identity, m.Module, &Error{codes.InvalidArgument, ReasonBackendRequired}, nil)
	}
	instance := req.GetInstanceId()
	if instance == "" || len(instance) > 64 {
		return r.refuse(identity, m.Module, &Error{codes.InvalidArgument, ReasonManifestInvalid}, map[string]any{"error": "instance_id required (≤ 64 chars)"})
	}
	entry, err := r.o.Allow.AllowBySpiffeID(ctx, identity)
	if errors.Is(err, store.ErrNotFound) {
		return r.refuse(identity, m.Module, &Error{codes.PermissionDenied, ReasonIdentityNotAllowed}, nil)
	}
	if err != nil {
		return Lease{}, &Error{codes.Unavailable, ReasonUnavailable}
	}
	if !contains(entry.Names, m.Module) {
		return r.refuse(identity, m.Module, &Error{codes.PermissionDenied, ReasonNameNotGranted}, nil)
	}
	for _, p := range m.Prefixes {
		if !granted(entry.Prefixes, p) {
			return r.refuse(identity, m.Module, &Error{codes.PermissionDenied, ReasonPrefixNotGranted}, map[string]any{"prefix": p})
		}
	}
	hash := hashManifest(m)
	now := r.o.Now()

	r.mu.Lock()
	switch r.marks[m.Module] {
	case "revoked":
		r.mu.Unlock()
		return r.refuse(identity, m.Module, &Error{codes.FailedPrecondition, ReasonModuleRevoked}, nil)
	case "draining":
		r.mu.Unlock()
		return r.refuse(identity, m.Module, &Error{codes.FailedPrecondition, ReasonModuleDraining}, nil)
	}
	subjects := map[string]string{}
	for _, other := range r.regs {
		if other.Module == m.Module {
			continue
		}
		for _, op := range other.Manifest.Prefixes {
			for _, p := range m.Prefixes {
				if manifest.Overlaps(op, p) {
					r.mu.Unlock()
					return r.refuse(identity, m.Module, &Error{codes.AlreadyExists, ReasonPrefixConflict}, map[string]any{"prefix": p, "owner": other.Module})
				}
			}
		}
		for _, s := range other.Manifest.Subjects() {
			subjects[s] = other.Module
		}
	}
	for _, s := range m.Subjects() {
		if owner, taken := subjects[s]; taken {
			r.mu.Unlock()
			return r.refuse(identity, m.Module, &Error{codes.AlreadyExists, ReasonSubjectConflict}, map[string]any{"subject": s, "owner": owner})
		}
	}
	reg := r.regs[m.Module]
	kind := EventRegistered
	auditType := audit.RegistrationAccepted
	switch {
	case reg == nil:
		reg = &Registration{Module: m.Module, Identity: identity, Manifest: m, Hash: hash, Instances: map[string]Instance{}, RegisteredAt: now}
	case reg.Identity != identity:
		r.mu.Unlock()
		return r.refuse(identity, m.Module, &Error{codes.PermissionDenied, ReasonIdentityMismatch}, nil)
	case reg.Hash == hash:
		kind = EventUpdated
	case newer(m.Version, reg.Manifest.Version):
		// A version bump replaces the manifest atomically; older instances
		// see their renewals refused (manifest_drift) and re-register.
		reg.Manifest, reg.Hash = m, hash
		kind, auditType = EventUpdated, audit.RegistrationUpdated
	default:
		r.mu.Unlock()
		return r.refuse(identity, m.Module, &Error{codes.FailedPrecondition, ReasonManifestDrift}, map[string]any{"registered_version": reg.Manifest.Version, "offered_version": m.Version})
	}
	leaseID := newID()
	if old, ok := reg.Instances[instance]; ok {
		r.leases = without(r.leases, old.LeaseID)
	}
	reg.Instances[instance] = Instance{ID: instance, Backend: be, LeaseID: leaseID, ManifestHash: hash, RegisteredAt: now, RenewedAt: now}
	reg.UpdatedAt = now
	r.regs[m.Module] = reg
	r.leases[leaseID] = leaseRef{m.Module, instance}
	if err := r.persistLocked(ctx, reg, instance, leaseID); err != nil {
		// Roll back the local mirror; the registrant retries.
		next := map[string]Instance{}
		for k, v := range reg.Instances {
			if k != instance {
				next[k] = v
			}
		}
		reg.Instances = next
		r.leases = without(r.leases, leaseID)
		if len(reg.Instances) == 0 {
			r.forgetLocked(m.Module)
		}
		r.mu.Unlock()
		r.o.Logger.Error("registry persist failed", "module", m.Module, "err", err)
		return Lease{}, &Error{codes.Unavailable, ReasonUnavailable}
	}
	r.rebuildLocked()
	r.mu.Unlock()
	v := r.announce(ctx, kind, m.Module)
	r.emit(audit.Event{Type: auditType, Module: m.Module, ActorKind: "service", ActorID: identity, Outcome: "ok", Reason: kind, SubjectKind: "instance", SubjectID: instance,
		Details: map[string]any{"prefixes": m.Prefixes, "version": m.Version, "routes": len(m.Routes), "methods": len(m.Methods)}})
	if r.o.OnAccepted != nil && kind == EventRegistered || r.o.OnAccepted != nil && auditType == audit.RegistrationUpdated {
		r.o.OnAccepted(ctx, m)
	}
	return Lease{ID: leaseID, Module: m.Module, Instance: instance, TTL: r.o.TTL, Renew: r.o.Renew, Version: v}, nil
}

func (r *Registry) persistLocked(ctx context.Context, reg *Registration, instance, leaseID string) error {
	raw, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	if err := r.o.KV.Set(ctx, regKey(reg.Module), string(raw), 0); err != nil {
		return err
	}
	if err := r.o.KV.Set(ctx, leaseKey(reg.Module, instance), leaseID, r.o.TTL); err != nil {
		return err
	}
	return r.o.KV.Set(ctx, leaseIndexKey(leaseID), reg.Module+"/"+instance, r.o.TTL)
}

// Renew extends a lease; refused after drain/revoke, on manifest drift or
// for an unknown lease (the registrant then re-registers).
func (r *Registry) Renew(ctx context.Context, identity, leaseID string) (Lease, error) {
	r.mu.Lock()
	ref, ok := r.leases[leaseID]
	if !ok {
		// Another gateway instance may have issued it: consult the KV.
		if v, found, err := r.o.KV.Get(ctx, leaseIndexKey(leaseID)); err == nil && found {
			if mod, inst, cut := strings.Cut(v, "/"); cut {
				if err := r.reloadLocked(ctx, mod); err == nil {
					ref, ok = leaseRef{mod, inst}, r.regs[mod] != nil && r.regs[mod].Instances[inst].LeaseID == leaseID
				}
			}
		}
	}
	if !ok {
		r.mu.Unlock()
		return r.refuseRenewal(identity, "", leaseID, ReasonUnknownLease, codes.NotFound)
	}
	reg := r.regs[ref.module]
	in := reg.Instances[ref.instance]
	switch {
	case reg.Identity != identity:
		r.mu.Unlock()
		return r.refuseRenewal(identity, ref.module, leaseID, ReasonIdentityMismatch, codes.PermissionDenied)
	case r.marks[ref.module] == "revoked":
		r.mu.Unlock()
		return r.refuseRenewal(identity, ref.module, leaseID, ReasonModuleRevoked, codes.FailedPrecondition)
	case r.marks[ref.module] == "draining":
		r.mu.Unlock()
		return r.refuseRenewal(identity, ref.module, leaseID, ReasonModuleDraining, codes.FailedPrecondition)
	case in.ManifestHash != reg.Hash:
		r.mu.Unlock()
		return r.refuseRenewal(identity, ref.module, leaseID, ReasonManifestDrift, codes.FailedPrecondition)
	}
	in.RenewedAt = r.o.Now()
	reg.Instances[ref.instance] = in
	if err := r.persistLocked(ctx, reg, ref.instance, leaseID); err != nil {
		r.mu.Unlock()
		r.o.Logger.Error("registry renew persist failed", "module", ref.module, "err", err)
		return Lease{}, &Error{codes.Unavailable, ReasonUnavailable}
	}
	r.mu.Unlock()
	return Lease{ID: leaseID, Module: ref.module, Instance: ref.instance, TTL: r.o.TTL, Renew: r.o.Renew, Version: r.version.Load()}, nil
}

// Deregister withdraws one instance immediately.
func (r *Registry) Deregister(ctx context.Context, identity, leaseID string) error {
	r.mu.Lock()
	ref, ok := r.leases[leaseID]
	if !ok || r.regs[ref.module].Identity != identity {
		r.mu.Unlock()
		return &Error{codes.NotFound, ReasonUnknownLease}
	}
	r.mu.Unlock()
	r.withdraw(ctx, ref.module, ref.instance, leaseID, "deregistered", identity)
	return nil
}

// withdraw removes an instance (and the module when it was the last one).
func (r *Registry) withdraw(ctx context.Context, module, instance, leaseID, reason, actor string) {
	r.mu.Lock()
	reg, ok := r.regs[module]
	if !ok {
		r.mu.Unlock()
		return
	}
	next := map[string]Instance{}
	for k, v := range reg.Instances {
		if k != instance {
			next[k] = v
		}
	}
	reg.Instances = next
	r.leases = without(r.leases, leaseID)
	if reg.Unhealthy != nil {
		nu := map[string]time.Time{}
		for k, v := range reg.Unhealthy {
			if k != instance {
				nu[k] = v
			}
		}
		reg.Unhealthy = nu
	}
	_ = r.o.KV.Del(ctx, leaseKey(module, instance), leaseIndexKey(leaseID))
	last := len(reg.Instances) == 0
	if last {
		r.forgetLocked(module)
		_ = r.o.KV.Del(ctx, regKey(module))
	} else if raw, err := json.Marshal(reg); err == nil {
		_ = r.o.KV.Set(ctx, regKey(module), string(raw), 0)
	}
	r.rebuildLocked()
	r.mu.Unlock()
	kind := "system"
	if actor != "" {
		kind = "service"
	}
	if last {
		r.announce(ctx, EventWithdrawn, module)
	} else {
		r.announce(ctx, EventUpdated, module)
	}
	r.emit(audit.Event{Type: audit.RegistrationWithdrawn, Module: module, ActorKind: kind, ActorID: actor, Outcome: "ok", Reason: reason, SubjectKind: "instance", SubjectID: instance, Details: map[string]any{"last_instance": last}})
}

// Sweep withdraws instances whose lease key expired in the KV.
func (r *Registry) Sweep(ctx context.Context) {
	type gone struct{ module, instance, lease string }
	var expired []gone
	r.mu.RLock()
	for _, reg := range r.regs {
		for _, in := range reg.Instances {
			if _, ok, err := r.o.KV.Get(ctx, leaseKey(reg.Module, in.ID)); err == nil && !ok {
				expired = append(expired, gone{reg.Module, in.ID, in.LeaseID})
			}
		}
	}
	r.mu.RUnlock()
	for _, g := range expired {
		r.withdraw(ctx, g.module, g.instance, g.lease, "lease_expired", "")
	}
}

// Run sweeps leases, refreshes marks and follows the pub/sub channel until ctx ends.
func (r *Registry) Run(ctx context.Context) error {
	if err := r.Load(ctx); err != nil {
		return err
	}
	go func() {
		for ctx.Err() == nil {
			err := r.o.KV.Subscribe(ctx, Channel, func(msg string) { r.onMessage(ctx, msg) })
			if ctx.Err() != nil {
				return
			}
			r.o.Logger.Warn("registry subscription ended; reconnecting", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	t := time.NewTicker(r.o.Sweep)
	defer t.Stop()
	marks := time.NewTicker(10 * r.o.Sweep)
	defer marks.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.Sweep(ctx)
		case <-marks.C:
			if err := r.RefreshMarks(ctx); err != nil {
				r.o.Logger.Warn("marks refresh failed", "err", err)
			}
		}
	}
}

// onMessage applies a change announced by another gateway instance.
func (r *Registry) onMessage(ctx context.Context, msg string) {
	var ev Event
	if err := json.Unmarshal([]byte(msg), &ev); err != nil || ev.Origin == r.o.Origin || !KnownEvent(ev.Kind) {
		return
	}
	r.mu.Lock()
	switch ev.Kind {
	case EventDrained, EventRevoked, EventRecovered:
		r.mu.Unlock()
		if err := r.RefreshMarks(ctx); err != nil {
			r.o.Logger.Warn("marks refresh failed", "err", err)
		}
		r.mu.Lock()
	default:
		if err := r.reloadLocked(ctx, ev.Module); err != nil {
			r.o.Logger.Warn("registry reload failed", "module", ev.Module, "err", err)
		}
	}
	if ev.Version > r.version.Load() {
		r.version.Store(ev.Version)
	}
	r.rebuildLocked()
	r.mu.Unlock()
	r.fanout(ev)
}

// announce bumps the version, records and publishes an event.
func (r *Registry) announce(ctx context.Context, kind, module string) uint64 {
	next := r.version.Load() + 1
	if v, err := r.o.KV.Incr(ctx, versionKey, 0); err == nil && v > 0 && uint64(v) > r.version.Load() {
		next = uint64(v)
	}
	r.version.Store(next)
	ev := Event{TS: r.o.Now(), Kind: kind, Module: module, Version: next, Origin: r.o.Origin}
	if raw, err := json.Marshal(ev); err == nil {
		_ = r.o.KV.Publish(ctx, Channel, string(raw))
	}
	r.fanout(ev)
	return ev.Version
}

func (r *Registry) fanout(ev Event) {
	r.wmu.Lock()
	r.events = append(r.events, ev)
	if len(r.events) > eventRing {
		r.events = append([]Event(nil), r.events[len(r.events)-eventRing:]...)
	}
	for id, ch := range r.watch {
		select {
		case ch <- ev:
		default:
			// Slow consumer: close so it re-watches from its cursor.
			close(ch)
			r.watch = withoutWatch(r.watch, id)
		}
	}
	r.wmu.Unlock()
}

func withoutWatch(m map[int]chan Event, id int) map[int]chan Event {
	next := make(map[int]chan Event, len(m))
	for k, v := range m {
		if k != id {
			next[k] = v
		}
	}
	return next
}

// Watch replays events after cursor (a registry version) and then streams
// live changes until cancel is called; the channel closes on overflow.
func (r *Registry) Watch(cursor uint64) (<-chan Event, func()) {
	ch := make(chan Event, 64)
	r.wmu.Lock()
	for _, ev := range r.events {
		if ev.Version > cursor && len(ch) < cap(ch) {
			ch <- ev
		}
	}
	id := r.nextW
	r.nextW++
	r.watch[id] = ch
	r.wmu.Unlock()
	return ch, func() {
		r.wmu.Lock()
		if c, ok := r.watch[id]; ok {
			close(c)
			r.watch = withoutWatch(r.watch, id)
		}
		r.wmu.Unlock()
	}
}

func (r *Registry) refuse(identity, module string, e *Error, details map[string]any) (Lease, error) {
	r.emit(audit.Event{Type: audit.RegistrationRefused, Module: module, ActorKind: "service", ActorID: identity, Outcome: "refused", Reason: e.Reason, Details: details})
	return Lease{}, e
}

func (r *Registry) refuseRenewal(identity, module, leaseID, reason string, code codes.Code) (Lease, error) {
	r.emit(audit.Event{Type: audit.RenewalRefused, Module: module, ActorKind: "service", ActorID: identity, Outcome: "refused", Reason: reason, SubjectKind: "lease", SubjectID: leaseID})
	return Lease{}, &Error{code, reason}
}

func (r *Registry) emit(e audit.Event) {
	if r.o.Audit != nil {
		_ = r.o.Audit.Emit(e)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// granted reports whether prefix is equal to or under one of the allowed prefixes.
func granted(allowed []string, prefix string) bool {
	for _, a := range allowed {
		if prefix == a || strings.HasPrefix(prefix, a+"/") {
			return true
		}
	}
	return false
}

// newer reports whether semantic version a is greater than b.
func newer(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) [3]int {
	var out [3]int
	for i, s := range strings.SplitN(v, ".", 3) {
		if i < 3 {
			out[i], _ = strconv.Atoi(s)
		}
	}
	return out
}

func hashManifest(m manifest.Manifest) string {
	raw, _ := json.Marshal(m)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

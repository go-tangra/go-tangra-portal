package httpapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// KnownStore is the known-module store the catalogue reads and changes.
type KnownStore interface {
	ListKnown(ctx context.Context) ([]store.KnownModule, error)
	SetKnownExpected(ctx context.Context, module string, expected bool) error
	ForgetKnown(ctx context.Context, module string) error
}

// CatalogueView is GET /gateway/v1/ops/catalogue.
type CatalogueView struct {
	// CanManage: the caller may change the catalogue (platform administrator).
	CanManage bool `json:"can_manage"`
	// Partial: the known-module store could not be read; only registered
	// modules are listed.
	Partial bool            `json:"partial,omitempty"`
	Items   []CatalogueItem `json:"items"`
}

// CatalogueItem is one module: its known record merged with the live registry.
type CatalogueItem struct {
	Module      string `json:"module"`
	DisplayName string `json:"display_name"`
	Identity    string `json:"identity"`
	// State: active | draining | unhealthy | revoked while registered;
	// down (expected) or stopped (not expected) when not.
	State         string   `json:"state"`
	Registered    bool     `json:"registered"`
	Instances     int      `json:"instances"`
	BuildVersions []string `json:"build_versions"`
	LastVersion   string   `json:"last_version"`
	FirstSeenAt   string   `json:"first_seen_at,omitempty"`
	LastSeenAt    string   `json:"last_seen_at,omitempty"`
	Expected      bool     `json:"expected"`
	// From the module's newest verified catalogue entry (spec 035).
	LatestVersion   string `json:"latest_version,omitempty"`
	Summary         string `json:"summary,omitempty"`
	Category        string `json:"category,omitempty"`
	Image           string `json:"image,omitempty"`
	Repository      string `json:"repository,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	Installable     bool   `json:"installable"`
}

// moduleNameRE is the catalogue's module name: a DNS label, as SPIFFE
// service paths use.
var moduleNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (s *Server) registerCatalogue(d OpsDeps) {
	if d.Sources != nil && d.Refresher != nil {
		s.registerCatalogueSources(d)
	}
	s.MustHandle("GET", "/gateway/v1/ops/catalogue", s.catalogueReader(d, func(w http.ResponseWriter, r *http.Request, id identity.Identity) {
		WriteJSON(w, http.StatusOK, buildCatalogue(r.Context(), d, s, r, IsAdmin(id, d.AdminRoles)))
	}))
	s.MustHandle("PATCH", "/gateway/v1/ops/catalogue/{module}", s.catalogueAdmin(d, "catalogue:expected", func(w http.ResponseWriter, r *http.Request, id identity.Identity, module string) {
		var in struct {
			Expected *bool `json:"expected"`
		}
		if err := DecodeJSON(r, &in); err != nil || in.Expected == nil {
			Fail(w, r, nil, ErrValidation)
			return
		}
		if err := d.Known.SetKnownExpected(r.Context(), module, *in.Expected); err != nil {
			Fail(w, r, s.rt.Logger(), knownErr(err))
			return
		}
		s.catalogueEvent(d, audit.KnownModuleExpected, id, module, map[string]any{"expected": *in.Expected})
		w.WriteHeader(http.StatusNoContent)
	}))
	s.MustHandle("DELETE", "/gateway/v1/ops/catalogue/{module}", s.catalogueAdmin(d, "catalogue:forget", func(w http.ResponseWriter, r *http.Request, id identity.Identity, module string) {
		if _, live := d.Reg.Get(module); live {
			Fail(w, r, nil, ErrConflict) // forgetting a registered module would be undone at once
			return
		}
		if err := d.Known.ForgetKnown(r.Context(), module); err != nil {
			Fail(w, r, s.rt.Logger(), knownErr(err))
			return
		}
		s.catalogueEvent(d, audit.KnownModuleForgotten, id, module, map[string]any{})
		w.WriteHeader(http.StatusNoContent)
	}))
}

// catalogueAdmin admits administrators of the platform tenant only; other
// callers are refused before the store is touched, and the refusal of an
// authenticated caller is audited.
func (s *Server) catalogueAdmin(d OpsDeps, action string, h func(http.ResponseWriter, *http.Request, identity.Identity, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireIdentity(w, r, d.Identity, s.rt.Logger())
		if !ok {
			return
		}
		module := r.PathValue("module")
		if !IsAdmin(id, d.AdminRoles) {
			if d.Events != nil {
				_ = d.Events.Emit(audit.Event{Type: audit.PermissionRefused, Module: module, ActorKind: "user", ActorID: id.UserID, TenantID: id.TenantID,
					Outcome: "refused", Reason: "not_catalogue_admin", Details: map[string]any{"permission": action}})
			}
			Fail(w, r, nil, ErrForbidden)
			return
		}
		if !moduleNameRE.MatchString(module) {
			Fail(w, r, nil, ErrValidation)
			return
		}
		h(w, r, id, module)
	}
}

func (s *Server) catalogueEvent(d OpsDeps, typ audit.EventType, id identity.Identity, module string, details map[string]any) {
	if d.Events != nil {
		_ = d.Events.Emit(audit.Event{Type: typ, Module: module, ActorKind: "operator", ActorID: id.UserID, TenantID: id.TenantID,
			SubjectKind: "module", SubjectID: module, Outcome: "ok", Details: details})
	}
}

func knownErr(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err // logged, answered as temporarily_unavailable
}

// catalogueReader admits platform-tenant members holding an operator or an
// administrator role.
func (s *Server) catalogueReader(d OpsDeps, h func(http.ResponseWriter, *http.Request, identity.Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireIdentity(w, r, d.Identity, s.rt.Logger())
		if !ok {
			return
		}
		if !IsOperator(id, d.Roles) && !IsAdmin(id, d.AdminRoles) {
			Fail(w, r, nil, ErrForbidden)
			return
		}
		h(w, r, id)
	}
}

// IsAdmin reports whether the caller belongs to the platform tenant and
// holds one of the administrator roles.
func IsAdmin(id identity.Identity, roles []string) bool {
	return IsOperator(id, roles)
}

func buildCatalogue(ctx context.Context, d OpsDeps, s *Server, r *http.Request, canManage bool) CatalogueView {
	v := CatalogueView{CanManage: canManage, Items: []CatalogueItem{}}
	live := map[string]registry.Registration{}
	for _, reg := range d.Reg.Registrations() {
		live[reg.Module] = reg
	}
	known, err := d.Known.ListKnown(ctx)
	if err != nil {
		// The registry still answers: list what is registered, flagged partial.
		s.rt.Logger().WarnContext(ctx, "known modules unavailable", "path", r.URL.Path)
		v.Partial = true
	}
	seen := map[string]bool{}
	for _, k := range known {
		seen[k.Module] = true
		it := CatalogueItem{Module: k.Module, DisplayName: k.DisplayName, Identity: k.Identity, LastVersion: k.LastVersion,
			FirstSeenAt: stamp(k.FirstSeenAt), LastSeenAt: stamp(k.LastSeenAt), Expected: k.Expected, BuildVersions: []string{}}
		if reg, ok := live[k.Module]; ok {
			liveItem(&it, d, reg)
		} else if k.Expected {
			it.State = "down"
		} else {
			it.State = "stopped"
		}
		v.Items = append(v.Items, it)
	}
	// Registered but not recorded yet (store write pending or failing).
	for name, reg := range live {
		if seen[name] {
			continue
		}
		it := CatalogueItem{Module: name, DisplayName: reg.Manifest.DisplayName, Identity: reg.Identity, Expected: true, BuildVersions: []string{}}
		liveItem(&it, d, reg)
		if vs := reg.BuildVersions(); len(vs) > 0 {
			it.LastVersion = vs[len(vs)-1]
		}
		v.Items = append(v.Items, it)
	}
	s.mergeEntries(ctx, d, &v)
	sort.Slice(v.Items, func(i, j int) bool { return v.Items[i].Module < v.Items[j].Module })
	return v
}

func liveItem(it *CatalogueItem, d OpsDeps, reg registry.Registration) {
	it.Registered = true
	it.State = string(d.Reg.State(reg.Module))
	it.Instances = len(reg.Instances)
	it.BuildVersions = nonNil(reg.BuildVersions())
	if it.DisplayName == "" {
		it.DisplayName = reg.Manifest.DisplayName
	}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

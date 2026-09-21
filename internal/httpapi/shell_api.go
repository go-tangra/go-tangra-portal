package httpapi

import (
	"context"
	"net/http"
	"sort"

	"github.com/go-freya/freya/services/gateway/internal/authz"
	"github.com/go-freya/freya/services/gateway/internal/registry"
)

// Decisions is what the shell API needs from the decider.
type Decisions interface {
	Held(ctx context.Context, tenant, user string, perms []string) (map[string]bool, error)
	Abilities(ctx context.Context, regs []registry.Registration, tenant, user string, roles []string, registryVersion uint64) (authz.AbilitiesDoc, error)
	TenantVersion(tenant string) string
}

// ShellDeps wire the shell API.
type ShellDeps struct {
	Reg      *registry.Registry
	Identity IdentitySource
	Decide   Decisions
	// Proxies builds forwarders for the remote asset relay.
	Proxies ProxyFactory
	// Hub is the platform realtime event bus; Instance names this gateway.
	Hub      EventHub
	Instance string
}

// ModuleView is one entry of GET /gateway/v1/me/modules.
type ModuleView struct {
	Module      string     `json:"module"`
	DisplayName string     `json:"display_name"`
	Version     string     `json:"version"`
	Remote      RemoteView `json:"remote"`
	Nav         []NavView  `json:"nav"`
	State       string     `json:"state"`
}

// RemoteView locates the federated remote.
type RemoteView struct {
	Entry     string   `json:"entry"`
	Exposes   []string `json:"exposes"`
	Integrity string   `json:"integrity,omitempty"`
}

// NavView is a permitted navigation entry.
type NavView struct {
	Title string `json:"title"`
	Path  string `json:"path"`
	Icon  string `json:"icon,omitempty"`
	Order int    `json:"order"`
}

// RegisterShell mounts the shell API and the remote relay.
func (s *Server) RegisterShell(d ShellDeps) {
	s.MustHandle("GET", "/gateway/v1/me/modules", s.myModules(d))
	s.MustHandle("GET", "/gateway/v1/me/abilities", s.myAbilities(d))
	s.MustHandle("GET", "/gateway/v1/events", s.events(d))
	s.MustHandle("GET", "/gateway/v1/stream", s.userStream(d))
	s.MustHandle("GET", "/m/{module}/{asset}", s.remoteAsset(d))
}

// visible lists registrations the shell may compose (revoked ones are hidden).
func visible(reg *registry.Registry) []registry.Registration {
	var out []registry.Registration
	for _, r := range reg.Registrations() {
		if st := reg.State(r.Module); st != registry.StateRevoked {
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) myModules(d ShellDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequireIdentity(w, r, d.Identity)
		if !ok {
			return
		}
		regs := visible(d.Reg)
		var perms []string
		for _, reg := range regs {
			for _, n := range reg.Manifest.Nav {
				perms = append(perms, n.Requires)
			}
		}
		held, err := d.Decide.Held(r.Context(), id.TenantID, id.UserID, perms)
		if err != nil {
			Fail(w, r, s.rt.Logger(), ErrUnavailable)
			return
		}
		out := make([]ModuleView, 0, len(regs))
		for _, reg := range regs {
			v := ModuleView{Module: reg.Module, DisplayName: reg.Manifest.DisplayName, Version: reg.Manifest.Version, State: string(d.Reg.State(reg.Module)),
				Remote: RemoteView{Entry: reg.Manifest.Remote.Entry, Exposes: nonNil(reg.Manifest.Remote.Exposes), Integrity: reg.Manifest.Remote.Integrity}, Nav: []NavView{}}
			for _, n := range reg.Manifest.Nav {
				if held[n.Requires] {
					v.Nav = append(v.Nav, NavView{Title: n.Title, Path: n.Path, Icon: n.Icon, Order: n.Order})
				}
			}
			sort.SliceStable(v.Nav, func(i, j int) bool { return v.Nav[i].Order < v.Nav[j].Order })
			out = append(out, v)
		}
		WriteJSON(w, http.StatusOK, out)
	}
}

func (s *Server) myAbilities(d ShellDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequireIdentity(w, r, d.Identity)
		if !ok {
			return
		}
		doc, err := d.Decide.Abilities(r.Context(), visible(d.Reg), id.TenantID, id.UserID, id.Roles, d.Reg.Version())
		if err != nil {
			Fail(w, r, s.rt.Logger(), ErrUnavailable)
			return
		}
		WriteJSON(w, http.StatusOK, doc)
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

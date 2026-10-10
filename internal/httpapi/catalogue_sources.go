package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	catsvc "github.com/go-tangra/go-tangra-portal/v4/internal/catalogue"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// CatalogueSources stores sources, allowed owners and verified entries.
type CatalogueSources interface {
	ListAllowedOwners(ctx context.Context) ([]string, error)
	ReplaceAllowedOwners(ctx context.Context, owners []string, by string) error
	ListSources(ctx context.Context) ([]store.CatalogueSource, error)
	AddSource(ctx context.Context, repo, by string) error
	RemoveSource(ctx context.Context, repo string) error
	LatestEntries(ctx context.Context) ([]store.CatalogueEntry, error)
}

// CatalogueRefresher reads and verifies releases (catalogue.Service).
type CatalogueRefresher interface {
	Refresh(ctx context.Context, repo string) catsvc.Result
	Upload(ctx context.Context, entry, bundle, attestation []byte) catsvc.Result
}

// SourceView is one catalogue source.
type SourceView struct {
	Repo          string `json:"repo"`
	Module        string `json:"module,omitempty"`
	LastCheckedAt string `json:"last_checked_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	AddedBy       string `json:"added_by"`
	AddedAt       string `json:"added_at"`
}

// upload part limits (catalogue.MaxEntryBytes etc. plus the attestation).
const maxUploadBytes = fwcat.MaxEntryBytes + fwcat.MaxBundleBytes + 64<<10 + 64<<10

func (s *Server) registerCatalogueSources(d OpsDeps) {
	s.MustHandle("GET", "/gateway/v1/ops/catalogue/sources", s.catalogueReader(d, func(w http.ResponseWriter, r *http.Request, _ identity.Identity) {
		sources, err := d.Sources.ListSources(r.Context())
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		owners, err := d.Sources.ListAllowedOwners(r.Context())
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		out := make([]SourceView, 0, len(sources))
		for _, src := range sources {
			v := SourceView{Repo: src.Repo, Module: src.Module, LastError: src.LastError, AddedBy: src.AddedBy, AddedAt: stamp(src.AddedAt)}
			if src.LastCheckedAt != nil {
				v.LastCheckedAt = stamp(*src.LastCheckedAt)
			}
			out = append(out, v)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"sources": out, "allowed_owners": nonNil(owners)})
	}))
	s.MustHandle("POST", "/gateway/v1/ops/catalogue/sources", s.catalogueAdminAny(d, "catalogue:sources", func(w http.ResponseWriter, r *http.Request, id identity.Identity) {
		var in struct {
			Repo string `json:"repo"`
		}
		if err := DecodeJSON(r, &in); err != nil || !fwcat.ValidRepository(in.Repo) {
			Fail(w, r, nil, ErrValidation)
			return
		}
		owner, _, _ := strings.Cut(in.Repo, "/")
		owners, err := d.Sources.ListAllowedOwners(r.Context())
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		if !containsFold(owners, owner) {
			Fail(w, r, nil, ErrValidation) // owner not allowed
			return
		}
		if err := d.Sources.AddSource(r.Context(), in.Repo, id.UserID); err != nil {
			if errors.Is(err, store.ErrConflict) {
				Fail(w, r, nil, ErrConflict)
				return
			}
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		s.catalogueEvent(d, audit.CatalogueSourceAdded, id, "", map[string]any{"repo": in.Repo})
		WriteJSON(w, http.StatusCreated, d.Refresher.Refresh(r.Context(), in.Repo))
	}))
	s.MustHandle("DELETE", "/gateway/v1/ops/catalogue/sources/{owner}/{repo}", s.catalogueAdminAny(d, "catalogue:sources", func(w http.ResponseWriter, r *http.Request, id identity.Identity) {
		repo, ok := pathRepo(r)
		if !ok {
			Fail(w, r, nil, ErrValidation)
			return
		}
		if err := d.Sources.RemoveSource(r.Context(), repo); err != nil {
			Fail(w, r, s.rt.Logger(), knownErr(err))
			return
		}
		s.catalogueEvent(d, audit.CatalogueSourceRemoved, id, "", map[string]any{"repo": repo})
		w.WriteHeader(http.StatusNoContent)
	}))
	s.MustHandle("POST", "/gateway/v1/ops/catalogue/sources/{owner}/{repo}/refresh", s.catalogueAdminAny(d, "catalogue:refresh", func(w http.ResponseWriter, r *http.Request, _ identity.Identity) {
		repo, ok := pathRepo(r)
		if !ok {
			Fail(w, r, nil, ErrValidation)
			return
		}
		sources, err := d.Sources.ListSources(r.Context())
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		for _, src := range sources {
			if strings.EqualFold(src.Repo, repo) {
				WriteJSON(w, http.StatusOK, d.Refresher.Refresh(r.Context(), src.Repo))
				return
			}
		}
		Fail(w, r, nil, ErrNotFound)
	}))
	s.MustHandle("PUT", "/gateway/v1/ops/catalogue/allowed-owners", s.catalogueAdminAny(d, "catalogue:owners", func(w http.ResponseWriter, r *http.Request, id identity.Identity) {
		var in struct {
			Owners []string `json:"owners"`
		}
		if err := DecodeJSON(r, &in); err != nil || len(in.Owners) == 0 || len(in.Owners) > 50 {
			Fail(w, r, nil, ErrValidation)
			return
		}
		for _, o := range in.Owners {
			if !fwcat.ValidOwner(o) {
				Fail(w, r, nil, ErrValidation)
				return
			}
		}
		if err := d.Sources.ReplaceAllowedOwners(r.Context(), in.Owners, id.UserID); err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		s.catalogueEvent(d, audit.AllowedOwnersChanged, id, "", map[string]any{"owners": in.Owners})
		w.WriteHeader(http.StatusNoContent)
	}))
	s.MustHandle("POST", "/gateway/v1/ops/catalogue/upload", s.catalogueAdminAny(d, "catalogue:upload", func(w http.ResponseWriter, r *http.Request, _ identity.Identity) {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
		mr, err := r.MultipartReader()
		if err != nil {
			Fail(w, r, nil, ErrValidation)
			return
		}
		parts := map[string][]byte{}
		limits := map[string]int64{"entry": fwcat.MaxEntryBytes, "bundle": fwcat.MaxBundleBytes, "attestation": 64 << 10}
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				Fail(w, r, nil, ErrValidation)
				return
			}
			limit, known := limits[p.FormName()]
			if !known {
				Fail(w, r, nil, ErrValidation)
				return
			}
			b, err := io.ReadAll(io.LimitReader(p, limit+1))
			if err != nil || int64(len(b)) > limit {
				Fail(w, r, nil, ErrTooLarge)
				return
			}
			parts[p.FormName()] = b
		}
		res := d.Refresher.Upload(r.Context(), parts["entry"], parts["bundle"], parts["attestation"])
		switch res.Outcome {
		case catsvc.OutcomeStored, catsvc.OutcomeCurrent:
			WriteJSON(w, http.StatusCreated, res)
		case catsvc.OutcomeUnavailable:
			Fail(w, r, s.rt.Logger(), errors.New(res.Error))
		default:
			WriteJSON(w, http.StatusBadRequest, map[string]any{"reason": ErrValidation.Reason, "detail": map[string]string{"error": res.Error}})
		}
	}))
}

// catalogueAdminAny is catalogueAdmin for routes without a {module}.
func (s *Server) catalogueAdminAny(d OpsDeps, action string, h func(http.ResponseWriter, *http.Request, identity.Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireIdentity(w, r, d.Identity, s.rt.Logger())
		if !ok {
			return
		}
		if !IsAdmin(id, d.AdminRoles) {
			if d.Events != nil {
				_ = d.Events.Emit(audit.Event{Type: audit.PermissionRefused, ActorKind: "user", ActorID: id.UserID, TenantID: id.TenantID,
					Outcome: "refused", Reason: "not_catalogue_admin", Details: map[string]any{"permission": action}})
			}
			Fail(w, r, nil, ErrForbidden)
			return
		}
		h(w, r, id)
	}
}

func pathRepo(r *http.Request) (string, bool) {
	repo := r.PathValue("owner") + "/" + r.PathValue("repo")
	return repo, fwcat.ValidRepository(repo)
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// mergeEntries adds each module's newest verified entry to the view and
// lists modules that have an entry but were never seen as available.
func (s *Server) mergeEntries(ctx context.Context, d OpsDeps, v *CatalogueView) {
	if d.Sources == nil {
		return
	}
	entries, err := d.Sources.LatestEntries(ctx)
	if err != nil {
		s.rt.Logger().WarnContext(ctx, "catalogue entries unavailable")
		v.Partial = true
		return
	}
	index := map[string]int{}
	for i, it := range v.Items {
		index[it.Module] = i
	}
	for _, row := range entries {
		e, err := fwcat.ParseEntry(row.Entry)
		if err != nil {
			continue // stored entries were verified; a schema change is skipped, not fatal
		}
		i, ok := index[e.Module]
		if !ok {
			v.Items = append(v.Items, CatalogueItem{Module: e.Module, DisplayName: e.DisplayName, State: "available", Expected: false, BuildVersions: []string{}})
			i = len(v.Items) - 1
		}
		it := &v.Items[i]
		it.LatestVersion, it.Summary, it.Category, it.Image, it.Repository, it.Installable = e.Version, e.Summary, e.Category, e.Image, e.Repository, true
		it.HostInputs, it.MinCore = e.HostInputs, e.MinCore
		for _, running := range it.BuildVersions {
			if c, err := fwcat.CompareVersions(running, e.Version); err == nil && c < 0 {
				it.UpdateAvailable = true
			}
		}
	}
}

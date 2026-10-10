package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	catsvc "github.com/go-tangra/go-tangra-portal/v4/internal/catalogue"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// JoinStore keeps join records and reads verified bundles.
type JoinStore interface {
	InsertJoin(ctx context.Context, j store.CatalogueJoin) error
	GetJoin(ctx context.Context, id string) (store.CatalogueJoin, error)
	EntryBundle(ctx context.Context, module, version string) ([]byte, error)
}

// JoinDeps make join bundles (spec 036).
type JoinDeps struct {
	// Core values written into every bundle (catalogue.CoreKeys).
	Core   map[string]string
	MeshCA func(ctx context.Context) ([]byte, error)
	Store  JoinStore
}

// JoinProgress is GET /gateway/v1/ops/catalogue/{module}/join/{id}.
type JoinProgress struct {
	ID          string       `json:"id"`
	Module      string       `json:"module"`
	Version     string       `json:"version"`
	CreatedAt   string       `json:"created_at"`
	ExpiresAt   string       `json:"expires_at"`
	TokenUsed   bool         `json:"token_used"`
	TokenUsedAt string       `json:"token_used_at,omitempty"`
	Registered  bool         `json:"registered"`
	State       string       `json:"state,omitempty"`
	LastRefusal *RefusalView `json:"last_refusal,omitempty"`
	Partial     bool         `json:"partial,omitempty"`
}

// RefusalView is a registration refusal since the join.
type RefusalView struct {
	Reason string `json:"reason"`
	At     string `json:"at"`
}

const (
	joinMaxTTL     = 24 * time.Hour
	joinDefaultTTL = 24 * time.Hour
)

func (s *Server) registerCatalogueJoin(d OpsDeps) {
	s.MustHandle("POST", "/gateway/v1/ops/catalogue/{module}/join", s.catalogueAdmin(d, "catalogue:join", func(w http.ResponseWriter, r *http.Request, id identity.Identity, module string) {
		if d.Join == nil || d.Enroll == nil {
			s.rt.Logger().WarnContext(r.Context(), "join bundles need catalogue.join (mesh addresses) and the auth enrolment client")
			Fail(w, r, nil, ErrUnavailable)
			return
		}
		var in struct {
			Inputs   map[string]string `json:"inputs"`
			TTLHours *int              `json:"ttl_hours"`
		}
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, ErrValidation)
			return
		}
		ttl := joinDefaultTTL
		if in.TTLHours != nil {
			ttl = time.Duration(*in.TTLHours) * time.Hour
			if ttl < time.Hour || ttl > joinMaxTTL {
				failParam(w, "ttl_hours")
				return
			}
		}
		entry, err := latestEntry(r.Context(), d, module)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		inputs, err := catsvc.CheckInputs(entry, in.Inputs)
		var ie *catsvc.InputError
		if errors.As(err, &ie) {
			failParam(w, ie.Key)
			return
		}
		bundle, err := d.Join.Store.EntryBundle(r.Context(), module, entry.Version)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		if err := entry.CheckBundle(bundle); err != nil {
			Fail(w, r, s.rt.Logger(), fmt.Errorf("stored bundle does not match its entry: %w", err))
			return
		}
		ca, err := d.Join.MeshCA(r.Context())
		if err != nil {
			Fail(w, r, s.rt.Logger(), fmt.Errorf("mesh CA: %w", err))
			return
		}
		spiffeID := "spiffe://" + d.TrustDomain + "/svc/" + module
		op := registry.Operator{UserID: id.UserID, TenantID: id.TenantID}
		if err := ensureAllow(r.Context(), d, entry, spiffeID, op); err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		minted, err := d.Enroll.MintEnrollmentToken(ctx, &authv1.MintEnrollmentTokenRequest{TenantId: d.Join.Core["MESH_TENANT_ID"],
			SpiffePaths: []string{spiffeID}, TtlSeconds: int64(ttl.Seconds())})
		if err != nil {
			if status.Code(err) == codes.InvalidArgument {
				Fail(w, r, s.rt.Logger(), fmt.Errorf("auth refused the join token: %w", err))
				return
			}
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		jti, err := catsvc.TokenJTI(minted.GetToken())
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		now := time.Now().UTC()
		zipped, err := catsvc.RenderJoin(catsvc.JoinRequest{Entry: entry, Bundle: bundle, Core: d.Join.Core, Inputs: inputs, Token: minted.GetToken(), MeshCA: ca, Now: now})
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		expires := now.Add(ttl)
		if minted.GetExpiresAt() != nil {
			expires = minted.GetExpiresAt().AsTime().UTC()
		}
		join := store.CatalogueJoin{ID: uuid.Must(uuid.NewV7()).String(), Module: module, Version: entry.Version, JTI: jti, MintedBy: id.UserID, CreatedAt: now, ExpiresAt: expires}
		if err := d.Join.Store.InsertJoin(r.Context(), join); err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		if d.Events != nil {
			_ = d.Events.Emit(audit.Event{Type: audit.ModuleJoinBundle, Module: module, ActorKind: "operator", ActorID: id.UserID, TenantID: id.TenantID,
				SubjectKind: "join", SubjectID: join.ID, Outcome: "ok", Details: map[string]any{"version": entry.Version, "jti": jti, "expires_at": stamp(expires)}})
		}
		h := w.Header()
		h.Set("Content-Type", "application/zip")
		h.Set("Content-Disposition", `attachment; filename="`+module+`-join.zip"`)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Join-Id", join.ID)
		h.Set("X-Join-Expires", stamp(expires))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zipped)
	}))
	s.MustHandle("GET", "/gateway/v1/ops/catalogue/{module}/join/{id}", s.catalogueAdmin(d, "catalogue:join", func(w http.ResponseWriter, r *http.Request, _ identity.Identity, module string) {
		if d.Join == nil || !uuidRE.MatchString(r.PathValue("id")) {
			Fail(w, r, nil, ErrNotFound)
			return
		}
		j, err := d.Join.Store.GetJoin(r.Context(), r.PathValue("id"))
		if err != nil || j.Module != module {
			Fail(w, r, s.rt.Logger(), knownErr(orNotFound(err)))
			return
		}
		p := JoinProgress{ID: j.ID, Module: j.Module, Version: j.Version, CreatedAt: stamp(j.CreatedAt), ExpiresAt: stamp(j.ExpiresAt)}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if st, err := d.Enroll.TokenStatus(ctx, &authv1.TokenStatusRequest{Jti: j.JTI}); err == nil {
			p.TokenUsed = st.GetConsumed()
			if st.GetConsumedAt() != nil {
				p.TokenUsedAt = stamp(st.GetConsumedAt().AsTime())
			}
		} else {
			p.Partial = true
		}
		if _, ok := d.Reg.Get(module); ok {
			p.Registered, p.State = true, string(d.Reg.State(module))
		}
		if d.Audit != nil {
			if rows, err := d.Audit.QueryAudit(r.Context(), module, string(audit.RegistrationRefused), j.CreatedAt, time.Now().UTC().Add(time.Minute), time.Time{}, 50); err == nil && len(rows) > 0 {
				sort.Slice(rows, func(a, b int) bool { return rows[a].TS.After(rows[b].TS) })
				p.LastRefusal = &RefusalView{Reason: rows[0].Reason, At: stamp(rows[0].TS)}
			}
		}
		WriteJSON(w, http.StatusOK, p)
	}))
}

// latestEntry is the module's newest verified entry (404 without one).
func latestEntry(ctx context.Context, d OpsDeps, module string) (fwcat.Entry, error) {
	rows, err := d.Sources.LatestEntries(ctx)
	if err != nil {
		return fwcat.Entry{}, err
	}
	for _, row := range rows {
		if row.Module == module {
			return fwcat.ParseEntry(row.Entry)
		}
	}
	return fwcat.Entry{}, ErrNotFound
}

// ensureAllow keeps an identical active allow-list entry, refuses a
// different one (409: an administrator resolves it on the allow-list page)
// and otherwise adds the entry's scope (re-checked: SR-004).
func ensureAllow(ctx context.Context, d OpsDeps, e fwcat.Entry, spiffeID string, op registry.Operator) error {
	if err := e.Validate(); err != nil {
		return ErrValidation
	}
	list, err := d.Ops.ListAllow(ctx)
	if err != nil {
		return err
	}
	for _, a := range list {
		if a.RevokedAt != nil || a.SpiffeID != spiffeID {
			continue
		}
		if sameSet(a.Prefixes, e.Routes.Prefixes) && sameSet(a.Names, e.Routes.Names) {
			return nil
		}
		return ErrConflict
	}
	_, err = d.Ops.AddAllow(ctx, store.AllowEntry{SpiffeID: spiffeID, Prefixes: append([]string{}, e.Routes.Prefixes...), Names: append([]string{}, e.Routes.Names...)}, op)
	return err
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

func orNotFound(err error) error {
	if err == nil {
		return store.ErrNotFound
	}
	return err
}

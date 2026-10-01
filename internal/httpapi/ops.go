package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/listquery"
)

// OpsDeps wire the operations API.
type OpsDeps struct {
	Reg      *registry.Registry
	Ops      *registry.Ops
	Identity IdentitySource
	Audit    audit.Querier
	Traffic  *Traffic
	// Roles that may operate the gateway (platform tenant members).
	Roles []string
}

// RegistrationView is one row of GET /gateway/v1/ops/registrations.
type RegistrationView struct {
	Module      string         `json:"module"`
	Identity    string         `json:"identity"`
	State       string         `json:"state"`
	Instances   int            `json:"instances"`
	Unhealthy   int            `json:"unhealthy"`
	LastRenewal string         `json:"last_renewal"`
	Manifest    map[string]any `json:"manifest"`
	Traffic     Snapshot       `json:"traffic"`
}

// AllowView is one allow-list row.
type AllowView struct {
	ID        string   `json:"id"`
	SpiffeID  string   `json:"spiffe_id"`
	Prefixes  []string `json:"prefixes"`
	Names     []string `json:"names"`
	CreatedBy string   `json:"created_by"`
	CreatedAt string   `json:"created_at"`
	RevokedAt string   `json:"revoked_at,omitempty"`
}

// RegisterOps mounts /gateway/v1/ops/* (operators only).
func (s *Server) RegisterOps(d OpsDeps) {
	s.MustHandle("GET", "/gateway/v1/ops/registrations", s.operator(d, s.listRegistrations(d)))
	s.MustHandle("POST", "/gateway/v1/ops/registrations/{module}/drain", s.operator(d, func(w http.ResponseWriter, r *http.Request, op registry.Operator) {
		s.opsResult(w, r, d.Ops.Drain(r.Context(), r.PathValue("module"), op))
	}))
	s.MustHandle("POST", "/gateway/v1/ops/registrations/{module}/undrain", s.operator(d, func(w http.ResponseWriter, r *http.Request, op registry.Operator) {
		s.opsResult(w, r, d.Ops.Undrain(r.Context(), r.PathValue("module"), op))
	}))
	s.MustHandle("POST", "/gateway/v1/ops/registrations/{module}/revoke", s.operator(d, func(w http.ResponseWriter, r *http.Request, op registry.Operator) {
		var in struct {
			Reason string `json:"reason"`
		}
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		s.opsResult(w, r, d.Ops.Revoke(r.Context(), r.PathValue("module"), in.Reason, op))
	}))
	s.MustHandle("GET", "/gateway/v1/ops/allowlist", s.operator(d, func(w http.ResponseWriter, r *http.Request, _ registry.Operator) {
		req, ok := parseList(w, r, store.AllowListList)
		if !ok {
			return
		}
		list, err := d.Ops.ListAllow(r.Context())
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		// The allow-list is small and operator-managed: sort and page it here.
		entries := make([]*store.AllowEntry, 0, len(list))
		for i := range list {
			entries = append(entries, &list[i])
		}
		listquery.SortSlice(entries, req, func(e *store.AllowEntry, field string) any {
			switch field {
			case "created_at":
				return e.CreatedAt
			case "revoked_at":
				if e.RevokedAt == nil {
					return nil
				}
				return *e.RevokedAt
			}
			return e.SpiffeID
		}, func(e *store.AllowEntry) string { return e.ID })
		page, total, applied := listquery.Window(entries, req)
		out := make([]AllowView, 0, len(page))
		for _, e := range page {
			out = append(out, allowView(*e))
		}
		WriteJSON(w, http.StatusOK, listquery.NewPage(out, total, applied))
	}))
	s.MustHandle("POST", "/gateway/v1/ops/allowlist", s.operator(d, func(w http.ResponseWriter, r *http.Request, op registry.Operator) {
		var in struct {
			SpiffeID string   `json:"spiffe_id"`
			Prefixes []string `json:"prefixes"`
			Names    []string `json:"names"`
		}
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		e, err := d.Ops.AddAllow(r.Context(), store.AllowEntry{SpiffeID: in.SpiffeID, Prefixes: in.Prefixes, Names: in.Names}, op)
		if err != nil {
			Fail(w, r, s.rt.Logger(), opsErr(err))
			return
		}
		WriteJSON(w, http.StatusCreated, allowView(e))
	}))
	s.MustHandle("POST", "/gateway/v1/ops/allowlist/{id}/revoke", s.operator(d, func(w http.ResponseWriter, r *http.Request, op registry.Operator) {
		s.opsResult(w, r, d.Ops.RevokeAllow(r.Context(), r.PathValue("id"), op))
	}))
	s.MustHandle("GET", "/gateway/v1/ops/audit", s.operator(d, s.opsAudit(d)))
}

type opsHandler func(w http.ResponseWriter, r *http.Request, op registry.Operator)

// operator resolves the caller and requires a platform operator role.
func (s *Server) operator(d OpsDeps, h opsHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireIdentity(w, r, d.Identity, s.rt.Logger())
		if !ok {
			return
		}
		if !IsOperator(id, d.Roles) {
			Fail(w, r, nil, ErrForbidden)
			return
		}
		h(w, r, registry.Operator{UserID: id.UserID, TenantID: id.TenantID})
	}
}

// IsOperator reports whether the caller belongs to the platform tenant and
// holds one of the operator roles.
func IsOperator(id identity.Identity, roles []string) bool {
	if !id.Operator {
		return false
	}
	for _, want := range roles {
		for _, have := range id.Roles {
			if have == want {
				return true
			}
		}
	}
	return false
}

func (s *Server) opsResult(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		Fail(w, r, s.rt.Logger(), opsErr(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func opsErr(err error) error {
	switch {
	case errors.Is(err, registry.ErrUnknownModule), errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, registry.ErrReason), errors.Is(err, registry.ErrAllowEntry), errors.Is(err, store.ErrConflict):
		return ErrValidation
	}
	return err
}

func allowView(e store.AllowEntry) AllowView {
	v := AllowView{ID: e.ID, SpiffeID: e.SpiffeID, Prefixes: nonNil(e.Prefixes), Names: nonNil(e.Names), CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339)}
	if e.RevokedAt != nil {
		v.RevokedAt = e.RevokedAt.UTC().Format(time.RFC3339)
	}
	return v
}

func (s *Server) listRegistrations(d OpsDeps) opsHandler {
	return func(w http.ResponseWriter, r *http.Request, _ registry.Operator) {
		req, ok := parseList(w, r, store.RegistrationList)
		if !ok {
			return
		}
		regs := d.Reg.Registrations()
		out := make([]RegistrationView, 0, len(regs))
		for _, reg := range regs {
			v := RegistrationView{Module: reg.Module, Identity: reg.Identity, State: string(d.Reg.State(reg.Module)), Instances: len(reg.Instances), Unhealthy: len(reg.Unhealthy),
				Manifest: map[string]any{"version": reg.Manifest.Version, "display_name": reg.Manifest.DisplayName, "prefixes": reg.Manifest.Prefixes, "routes": len(reg.Manifest.Routes), "methods": len(reg.Manifest.Methods), "permissions": len(reg.Manifest.Permissions), "abilities": len(reg.Manifest.Abilities)}}
			var last time.Time
			for _, in := range reg.Instances {
				if in.RenewedAt.After(last) {
					last = in.RenewedAt
				}
			}
			if !last.IsZero() {
				v.LastRenewal = last.UTC().Format(time.RFC3339)
			}
			if d.Traffic != nil {
				v.Traffic = d.Traffic.Snapshot(reg.Module)
			}
			out = append(out, v)
		}
		views := make([]*RegistrationView, 0, len(out))
		for i := range out {
			views = append(views, &out[i])
		}
		listquery.SortSlice(views, req, func(v *RegistrationView, field string) any {
			switch field {
			case "state":
				return v.State
			case "instances":
				return v.Instances
			case "last_renewal":
				if v.LastRenewal == "" {
					return nil
				}
				return v.LastRenewal // RFC 3339 UTC sorts as text
			}
			return v.Module
		}, func(v *RegistrationView) string { return v.Module })
		page, total, applied := listquery.Window(views, req)
		items := make([]RegistrationView, 0, len(page))
		for _, v := range page {
			items = append(items, *v)
		}
		WriteJSON(w, http.StatusOK, listquery.NewPage(items, total, applied))
	}
}

func (s *Server) opsAudit(d OpsDeps) opsHandler {
	return func(w http.ResponseWriter, r *http.Request, op registry.Operator) {
		q := r.URL.Query()
		if !listquery.Legacy(q) {
			s.opsAuditPage(d)(w, r, op)
			return
		}
		// Legacy cursor paging (one release; specs/032 research D7).
		f := audit.Filter{Module: q.Get("module"), EventType: q.Get("event_type"), Limit: 100}
		var err error
		if f.From, err = parseTime(q, "from"); err != nil {
			Fail(w, r, nil, ErrValidation)
			return
		}
		if f.To, err = parseTime(q, "to"); err != nil {
			Fail(w, r, nil, ErrValidation)
			return
		}
		if f.Cursor, err = parseTime(q, "cursor"); err != nil {
			Fail(w, r, nil, ErrValidation)
			return
		}
		rows, err := audit.Query(r.Context(), d.Audit, f, time.Now())
		if errors.Is(err, audit.ErrSpan) {
			failParam(w, "from")
			return
		}
		if err != nil {
			Fail(w, r, s.rt.Logger(), ErrValidation)
			return
		}
		out := struct {
			Events []AuditView `json:"events"`
			Next   string      `json:"next_cursor,omitempty"`
		}{Events: []AuditView{}}
		for i := range rows {
			out.Events = append(out.Events, auditView(&rows[i]))
		}
		if len(rows) == f.Limit {
			out.Next = rows[len(rows)-1].TS.UTC().Format(time.RFC3339Nano)
		}
		WriteJSON(w, http.StatusOK, out)
	}
}

// AuditView is one gateway audit event in the ops API.
type AuditView struct {
	ID            int64  `json:"id,omitempty"`
	TS            string `json:"ts"`
	EventType     string `json:"event_type"`
	Module        string `json:"module"`
	ActorKind     string `json:"actor_kind"`
	ActorID       string `json:"actor_id"`
	SubjectKind   string `json:"subject_kind"`
	SubjectID     string `json:"subject_id"`
	Outcome       string `json:"outcome"`
	Reason        string `json:"reason"`
	CorrelationID string `json:"correlation_id"`
	Details       any    `json:"details"`
}

func auditView(e *store.AuditRow) AuditView {
	return AuditView{ID: e.ID, TS: e.TS.UTC().Format(time.RFC3339Nano), EventType: e.EventType, Module: e.Module, ActorKind: e.ActorKind, ActorID: e.ActorID,
		SubjectKind: e.SubjectKind, SubjectID: e.SubjectID, Outcome: e.Outcome, Reason: e.Reason, CorrelationID: e.CorrelationID, Details: rawJSON(e.Details)}
}

// opsAuditPage serves the list contract: page/page_size/sort/order within the
// module/event_type/from/to filters (default window: the last 7 days; a
// range wider than audit.MaxAuditSpan is refused naming "from").
func (s *Server) opsAuditPage(d OpsDeps) opsHandler {
	return func(w http.ResponseWriter, r *http.Request, _ registry.Operator) {
		req, ok := parseList(w, r, store.AuditList)
		if !ok {
			return
		}
		q := r.URL.Query()
		f := audit.Filter{Module: q.Get("module"), EventType: q.Get("event_type")}
		var err error
		if f.From, err = parseTime(q, "from"); err != nil {
			failParam(w, "from")
			return
		}
		if f.To, err = parseTime(q, "to"); err != nil {
			failParam(w, "to")
			return
		}
		rows, total, applied, err := audit.QueryPage(r.Context(), d.Audit, f, req, time.Now())
		if err != nil {
			if errors.Is(err, audit.ErrSpan) {
				failParam(w, "from")
				return
			}
			if errors.Is(err, audit.ErrFilter) {
				Fail(w, r, nil, ErrValidation)
				return
			}
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		items := make([]AuditView, 0, len(rows))
		for i := range rows {
			items = append(items, auditView(&rows[i]))
		}
		WriteJSON(w, http.StatusOK, listquery.NewPage(items, total, applied))
	}
}

// parseList validates the list parameters; on failure it answers
// validation_failed naming the parameter (never echoing the value).
func parseList(w http.ResponseWriter, r *http.Request, spec listquery.Spec) (listquery.Request, bool) {
	req, err := listquery.Parse(r.URL.Query(), spec)
	var le *listquery.Error
	if errors.As(err, &le) {
		failParam(w, le.Param)
		return req, false
	}
	return req, true
}

func failParam(w http.ResponseWriter, param string) {
	WriteJSON(w, ErrValidation.Status, map[string]any{"reason": ErrValidation.Reason, "detail": map[string]string{"param": param}})
}

func parseTime(q url.Values, key string) (time.Time, error) {
	v := q.Get(key)
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, v)
}

type rawMessage []byte

func (r rawMessage) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("{}"), nil
	}
	return r, nil
}

func rawJSON(b []byte) any { return rawMessage(b) }

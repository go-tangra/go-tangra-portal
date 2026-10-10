package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	catsvc "github.com/go-tangra/go-tangra-portal/v4/internal/catalogue"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// TargetView is one host of GET /gateway/v1/ops/catalogue/{module}/targets.
type TargetView struct {
	HostID      string   `json:"host_id"`
	Hostname    string   `json:"hostname"`
	OSName      string   `json:"os_name"`
	AgentOnline bool     `json:"agent_online"`
	Capability  string   `json:"capability"`
	IPAddresses []string `json:"ip_addresses"`
}

// DeliveryView is an agent delivery's state, as the inventory reports it.
type DeliveryView struct {
	HostID       string `json:"host_id"`
	Hostname     string `json:"hostname"`
	State        string `json:"state"`
	Reason       string `json:"reason,omitempty"`
	AgentOnline  bool   `json:"agent_online"`
	HookExitCode *int32 `json:"hook_exit_code,omitempty"`
}

// targetReasons are the host eligibility refusals the inventory names.
var targetReasons = map[string]bool{"no_agent": true, "upgrade_required": true, "ambiguous_agent": true, "not_supported_platform": true,
	"disabled_on_host": true, "disabled_on_server": true, "retired": true}

func deliveryView(d *inventoryv1.ModuleDelivery) *DeliveryView {
	v := &DeliveryView{HostID: d.GetHostId(), Hostname: d.GetHostname(), Reason: d.GetReason(), AgentOnline: d.GetAgentOnline(),
		State: strings.ToLower(strings.TrimPrefix(d.GetState().String(), "MODULE_DELIVERY_STATE_"))}
	if c := d.GetHookExitCode(); c >= 0 && d.GetState() != inventoryv1.ModuleDeliveryState_MODULE_DELIVERY_STATE_PENDING {
		v.HookExitCode = &c
	}
	return v
}

func (s *Server) registerCatalogueDeliver(d OpsDeps) {
	s.MustHandle("GET", "/gateway/v1/ops/catalogue/{module}/targets", s.catalogueAdmin(d, "catalogue:join", func(w http.ResponseWriter, r *http.Request, id identity.Identity, module string) {
		if d.Inventory == nil {
			Fail(w, r, nil, ErrUnavailable)
			return
		}
		if _, err := latestEntry(r.Context(), d, module); err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		q := r.URL.Query().Get("q")
		if len(q) > 64 {
			failParam(w, "q")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		res, err := d.Inventory.ListModuleTargets(ctx, &inventoryv1.ListModuleTargetsRequest{TenantId: id.TenantID, Query: q, Limit: 100})
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		out := struct {
			Hosts     []TargetView `json:"hosts"`
			Truncated bool         `json:"truncated"`
		}{Hosts: []TargetView{}, Truncated: res.GetTruncated()}
		for _, h := range res.GetHosts() {
			out.Hosts = append(out.Hosts, TargetView{HostID: h.GetHostId(), Hostname: h.GetHostname(), OSName: h.GetOsName(), AgentOnline: h.GetAgentOnline(),
				Capability: h.GetCapability(), IPAddresses: append([]string{}, h.GetIpAddresses()...)})
		}
		WriteJSON(w, http.StatusOK, out)
	}))
	s.MustHandle("POST", "/gateway/v1/ops/catalogue/{module}/deliver", s.catalogueAdmin(d, "catalogue:join", func(w http.ResponseWriter, r *http.Request, id identity.Identity, module string) {
		if d.Join == nil || d.Enroll == nil || d.Inventory == nil {
			s.rt.Logger().WarnContext(r.Context(), "agent delivery needs catalogue.join, catalogue.agent_delivery and the auth enrolment client")
			Fail(w, r, nil, ErrUnavailable)
			return
		}
		var in struct {
			HostID   string            `json:"host_id"`
			Inputs   map[string]string `json:"inputs"`
			TTLHours *int              `json:"ttl_hours"`
		}
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, ErrValidation)
			return
		}
		if !uuidRE.MatchString(in.HostID) {
			failParam(w, "host_id")
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
		spiffeID := "spiffe://" + d.TrustDomain + "/svc/" + module
		if err := ensureAllow(r.Context(), d, entry, spiffeID, registry.Operator{UserID: id.UserID, TenantID: id.TenantID}); err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		now := time.Now().UTC()
		join := store.CatalogueJoin{ID: uuid.Must(uuid.NewV7()).String(), Module: module, Version: entry.Version, MintedBy: id.UserID, CreatedAt: now,
			ExpiresAt: now.Add(ttl), Channel: store.JoinAgent, TenantID: id.TenantID, HostID: in.HostID, Inputs: inputs}
		if err := d.Join.Store.InsertJoin(r.Context(), join); err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		del, err := d.Inventory.CreateModuleDelivery(ctx, &inventoryv1.CreateModuleDeliveryRequest{TenantId: id.TenantID, DeliveryId: join.ID,
			HostId: in.HostID, Module: module, Version: entry.Version, ExpiresAt: join.ExpiresAt.Unix()})
		if err != nil {
			s.deliveryRefused(w, r, d, id, module, join, err)
			return
		}
		if d.Events != nil {
			_ = d.Events.Emit(audit.Event{Type: audit.ModuleJoinBundle, Module: module, ActorKind: "operator", ActorID: id.UserID, TenantID: id.TenantID,
				SubjectKind: "join", SubjectID: join.ID, Outcome: "ok", Details: map[string]any{"version": entry.Version, "channel": store.JoinAgent,
					"host_id": in.HostID, "item_id": del.GetItemId(), "expires_at": stamp(join.ExpiresAt)}})
		}
		WriteJSON(w, http.StatusAccepted, map[string]any{"join_id": join.ID, "expires_at": stamp(join.ExpiresAt), "delivery": deliveryView(del)})
	}))
}

// deliveryRefused maps an inventory refusal: unknown host 404, ineligible
// host 409 with the reason, a bad request 400, anything else 503.
func (s *Server) deliveryRefused(w http.ResponseWriter, r *http.Request, d OpsDeps, id identity.Identity, module string, join store.CatalogueJoin, err error) {
	st, _ := status.FromError(err)
	reason := ""
	switch st.Code() {
	case codes.NotFound:
		reason = "unknown_host"
	case codes.FailedPrecondition:
		if targetReasons[st.Message()] {
			reason = st.Message()
		} else {
			reason = "not_eligible"
		}
	case codes.InvalidArgument:
		reason = "invalid_request"
	}
	if d.Events != nil {
		_ = d.Events.Emit(audit.Event{Type: audit.ModuleJoinBundle, Module: module, ActorKind: "operator", ActorID: id.UserID, TenantID: id.TenantID,
			SubjectKind: "join", SubjectID: join.ID, Outcome: "refused", Reason: reasonOr(reason, "inventory_unavailable"),
			Details: map[string]any{"channel": store.JoinAgent, "host_id": join.HostID}})
	}
	switch st.Code() {
	case codes.NotFound:
		Fail(w, r, nil, ErrNotFound)
	case codes.FailedPrecondition:
		WriteJSON(w, ErrConflict.Status, map[string]any{"reason": ErrConflict.Reason, "detail": map[string]string{"reason": reason}})
	case codes.InvalidArgument:
		failParam(w, "host_id")
	default:
		Fail(w, r, s.rt.Logger(), err)
	}
}

func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}

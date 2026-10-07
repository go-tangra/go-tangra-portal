package httpapi

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
)

// Enrolment tokens (the console equivalent of `authsvc mint-enrollment-token`):
// an operator mints a single-use lcm join token for one or more services of
// this trust domain; the service presents it once for its first SVID.
const (
	// MeshTenantID is lcm's mesh CA tenant: SVIDs issued under it chain to the
	// one mesh root every workload trusts (the CLI's default -tenant).
	MeshTenantID = "00000000-0000-0000-0000-000000000001"
	// Enrolment token lifetimes auth accepts (it caps them at 30 minutes).
	EnrollMinTTL     = time.Minute
	EnrollMaxTTL     = 30 * time.Minute
	EnrollDefaultTTL = 10 * time.Minute
	// EnrollMaxServices bounds one token's SPIFFE ids.
	EnrollMaxServices = 10
)

var (
	serviceNameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	uuidRE        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// EnrollmentRequest is the POST /gateway/v1/ops/enrollment-tokens body.
type EnrollmentRequest struct {
	// Services are service names ("sms-gw") or SPIFFE ids of this trust
	// domain ("spiffe://<td>/svc/sms-gw").
	Services   []string `json:"services"`
	TenantID   string   `json:"tenant_id,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
}

// EnrollmentToken is the minted token, shown once and never stored.
type EnrollmentToken struct {
	Token     string   `json:"token"`
	ExpiresAt string   `json:"expires_at"`
	SpiffeIDs []string `json:"spiffe_ids"`
	TenantID  string   `json:"tenant_id"`
}

// spiffeIDs turns service names or SPIFFE ids into this trust domain's
// spiffe://<td>/svc/<name> ids (deduplicated, in order); false when one is
// malformed or names another trust domain.
func spiffeIDs(trustDomain string, in []string) ([]string, bool) {
	prefix := "spiffe://" + trustDomain + "/svc/"
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		name := strings.TrimSpace(s)
		if strings.HasPrefix(name, "spiffe://") {
			if !strings.HasPrefix(name, prefix) {
				return nil, false
			}
			name = strings.TrimPrefix(name, prefix)
		}
		if !serviceNameRE.MatchString(name) {
			return nil, false
		}
		if id := prefix + name; !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, len(out) > 0
}

// mintEnrollment handles POST /gateway/v1/ops/enrollment-tokens (operators).
// The token goes to the caller only: never logged, audited or stored.
func (s *Server) mintEnrollment(d OpsDeps) opsHandler {
	return func(w http.ResponseWriter, r *http.Request, op registry.Operator) {
		var in EnrollmentRequest
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if len(in.Services) == 0 || len(in.Services) > EnrollMaxServices {
			failParam(w, "services")
			return
		}
		ids, ok := spiffeIDs(d.TrustDomain, in.Services)
		if !ok {
			failParam(w, "services")
			return
		}
		tenant := strings.TrimSpace(in.TenantID)
		if tenant == "" {
			tenant = MeshTenantID
		}
		if !uuidRE.MatchString(tenant) {
			failParam(w, "tenant_id")
			return
		}
		ttl := EnrollDefaultTTL
		if in.TTLSeconds != 0 {
			ttl = time.Duration(in.TTLSeconds) * time.Second
		}
		// auth would silently shorten a longer one: refuse instead.
		if ttl < EnrollMinTTL || ttl > EnrollMaxTTL {
			failParam(w, "ttl_seconds")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		res, err := d.Enroll.MintEnrollmentToken(ctx, &authv1.MintEnrollmentTokenRequest{TenantId: tenant, SpiffePaths: ids, TtlSeconds: int64(ttl.Seconds())})
		outcome, reason := "ok", ""
		if err != nil {
			outcome, reason = "failed", status.Code(err).String()
		}
		if d.Events != nil {
			_ = d.Events.Emit(audit.Event{Type: audit.EnrollmentTokenMinted, ActorKind: "operator", ActorID: op.UserID, TenantID: op.TenantID, SubjectKind: "spiffe_id",
				SubjectID: strings.Join(ids, ","), Outcome: outcome, Reason: reason, Details: map[string]any{"tenant_id": tenant, "ttl_seconds": int(ttl.Seconds())}})
		}
		if err != nil {
			if status.Code(err) == codes.InvalidArgument {
				Fail(w, r, nil, ErrValidation)
				return
			}
			Fail(w, r, s.rt.Logger(), ErrUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		WriteJSON(w, http.StatusCreated, EnrollmentToken{Token: res.GetToken(), ExpiresAt: res.GetExpiresAt().AsTime().UTC().Format(time.RFC3339), SpiffeIDs: ids, TenantID: tenant})
	}
}

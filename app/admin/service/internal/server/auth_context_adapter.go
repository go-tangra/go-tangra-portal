package server

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/go-tangra/go-tangra-common/grpcx"
	"github.com/go-tangra/go-tangra-portal/pkg/middleware/auth"
)

// defaultClaimsTTL bounds how long a gateway claim assertion is accepted
// downstream. Request fan-out completes in seconds, so a few minutes is ample
// while keeping the replay window small.
const defaultClaimsTTL = 5 * time.Minute

// AuthContextAdapter implements gateway/transcoder.AuthContextProvider
// by extracting JWT claims from the Kratos auth middleware context.
type AuthContextAdapter struct {
	// signingSecret is the HMAC key used to sign the derived claims so modules
	// can prove they originated here (CRIT-3.2 / MED-2). Empty disables signing.
	signingSecret []byte
	// signingTTL is how long a signed assertion remains valid.
	signingTTL time.Duration
}

// NewAuthContextAdapter creates a new AuthContextAdapter, loading the claims
// signing secret and TTL from the environment.
func NewAuthContextAdapter() *AuthContextAdapter {
	ttl := defaultClaimsTTL
	if s := os.Getenv("CLAIMS_SIGNING_TTL_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			ttl = time.Duration(n) * time.Second
		}
	}
	return &AuthContextAdapter{
		signingSecret: []byte(os.Getenv("CLAIMS_SIGNING_SECRET")),
		signingTTL:    ttl,
	}
}

// GetTenantID returns the tenant ID from the authenticated request context.
func (a *AuthContextAdapter) GetTenantID(ctx context.Context) (uint32, bool) {
	tokenPayload, err := auth.FromContext(ctx)
	if err != nil || tokenPayload == nil {
		return 0, false
	}
	return tokenPayload.GetTenantId(), true
}

// InjectGRPCMetadata builds outgoing gRPC metadata from the auth context. In
// addition to the x-md-global-* claims it emits a gateway HMAC over those
// claims (x-md-global-claims-sig / -exp) so downstream modules can distinguish
// gateway-derived claims from ones forged by a direct mTLS caller.
func (a *AuthContextAdapter) InjectGRPCMetadata(ctx context.Context, _ *http.Request) metadata.MD {
	md := metadata.New(nil)

	tokenPayload, err := auth.FromContext(ctx)
	if err != nil || tokenPayload == nil {
		return md
	}

	// Compute the exact string values that go on the wire (and are signed).
	// Absent username/roles are signed as "" — the verifier reads a missing
	// key as "" too, so signer and verifier agree byte-for-byte.
	tenantID := strconv.FormatUint(uint64(tokenPayload.GetTenantId()), 10)
	userID := strconv.FormatUint(uint64(tokenPayload.GetUserId()), 10)
	username := ""
	if tokenPayload.Username != nil {
		username = *tokenPayload.Username
	}
	roles := ""
	if r := tokenPayload.GetRoles(); len(r) > 0 {
		roles = strings.Join(r, ",")
	}

	md.Set(grpcx.MDTenantID, tenantID)
	md.Set(grpcx.MDUserID, userID)
	if username != "" {
		md.Set(grpcx.MDUsername, username)
	}
	if roles != "" {
		md.Set(grpcx.MDRoles, roles)
	}

	// Sign the claims so modules can bind them to the gateway. Skipped when no
	// secret is configured (backward-compatible; modules fall back to warn).
	if len(a.signingSecret) > 0 {
		exp := time.Now().Add(a.signingTTL).Unix()
		sig := grpcx.SignClaims(a.signingSecret, tenantID, userID, username, roles, exp)
		md.Set(grpcx.MDClaimsSig, sig)
		md.Set(grpcx.MDClaimsExp, strconv.FormatInt(exp, 10))
	}

	return md
}

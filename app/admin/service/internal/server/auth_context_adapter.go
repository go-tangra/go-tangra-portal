package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc/metadata"

	"github.com/go-tangra/go-tangra-portal/pkg/middleware/auth"
)

// AuthContextAdapter implements gateway/transcoder.AuthContextProvider
// by extracting JWT claims from the Kratos auth middleware context.
type AuthContextAdapter struct{}

// NewAuthContextAdapter creates a new AuthContextAdapter.
func NewAuthContextAdapter() *AuthContextAdapter {
	return &AuthContextAdapter{}
}

// GetTenantID returns the tenant ID from the authenticated request context.
func (a *AuthContextAdapter) GetTenantID(ctx context.Context) (uint32, bool) {
	tokenPayload, err := auth.FromContext(ctx)
	if err != nil || tokenPayload == nil {
		return 0, false
	}
	return tokenPayload.GetTenantId(), true
}

// InjectGRPCMetadata builds outgoing gRPC metadata from the auth context.
func (a *AuthContextAdapter) InjectGRPCMetadata(ctx context.Context, _ *http.Request) metadata.MD {
	md := metadata.New(nil)

	tokenPayload, err := auth.FromContext(ctx)
	if err != nil || tokenPayload == nil {
		return md
	}

	md.Set("x-md-global-tenant-id", strconv.FormatUint(uint64(tokenPayload.GetTenantId()), 10))
	md.Set("x-md-global-user-id", strconv.FormatUint(uint64(tokenPayload.GetUserId()), 10))
	if tokenPayload.Username != nil {
		md.Set("x-md-global-username", *tokenPayload.Username)
	}
	if roles := tokenPayload.GetRoles(); len(roles) > 0 {
		md.Set("x-md-global-roles", strings.Join(roles, ","))
	}

	return md
}

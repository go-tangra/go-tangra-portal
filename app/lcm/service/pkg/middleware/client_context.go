package middleware

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
)

// ClientContextHelper provides utility methods for working with client context in services
type ClientContextHelper struct {
	log *log.Helper
}

// NewClientContextHelper creates a new client context helper
func NewClientContextHelper(logger log.Logger) *ClientContextHelper {
	return &ClientContextHelper{
		log: log.NewHelper(log.With(logger, "module", "client-context")),
	}
}

// LogClientInfo logs information about the authenticated client
func (h *ClientContextHelper) LogClientInfo(ctx context.Context, operation string) {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok && clientInfo != nil {
		if clientInfo.IsAuthenticated {
			h.log.Infof("Authenticated client for %s: CN=%s, Org=%v, Serial=%s", 
				operation, clientInfo.CommonName, clientInfo.Organizations, clientInfo.SerialNumber)
		} else {
			h.log.Infof("Unauthenticated request for %s", operation)
		}
	} else {
		h.log.Infof("No client info available for %s", operation)
	}
}

// RequireAuthentication checks if the client is authenticated and returns an error if not
func (h *ClientContextHelper) RequireAuthentication(ctx context.Context) error {
	if !IsClientAuthenticated(ctx) {
		return fmt.Errorf("client authentication required")
	}
	return nil
}

// GetClientCommonName returns the common name from the client certificate
func (h *ClientContextHelper) GetClientCommonName(ctx context.Context) string {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok && clientInfo != nil {
		return clientInfo.CommonName
	}
	return ""
}

// GetClientOrganizations returns the organizations from the client certificate
func (h *ClientContextHelper) GetClientOrganizations(ctx context.Context) []string {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok && clientInfo != nil {
		return clientInfo.Organizations
	}
	return nil
}

// GetClientSerialNumber returns the serial number from the client certificate
func (h *ClientContextHelper) GetClientSerialNumber(ctx context.Context) string {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok && clientInfo != nil {
		return clientInfo.SerialNumber
	}
	return ""
}

// ValidateClientOrganization checks if the client belongs to a specific organization
func (h *ClientContextHelper) ValidateClientOrganization(ctx context.Context, requiredOrg string) error {
	clientInfo, ok := GetClientInfoFromContext(ctx)
	if !ok || clientInfo == nil {
		return fmt.Errorf("no client information available")
	}
	
	if !clientInfo.IsAuthenticated {
		return fmt.Errorf("client not authenticated")
	}
	
	for _, org := range clientInfo.Organizations {
		if org == requiredOrg {
			return nil
		}
	}
	
	return fmt.Errorf("client not authorized: organization %s required", requiredOrg)
}
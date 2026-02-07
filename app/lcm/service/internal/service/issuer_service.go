package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// IssuerService implements the LcmIssuerService gRPC service
type IssuerService struct {
	lcmV1.UnimplementedLcmIssuerServiceServer

	log          *log.Helper
	issuerRepo   *data.IssuerRepo
	clientRepo   *data.LcmClientRepo
	mtlsCertRepo *data.MtlsCertificateRepo
}

// NewIssuerService creates a new IssuerService
func NewIssuerService(
	ctx *bootstrap.Context,
	issuerRepo *data.IssuerRepo,
	clientRepo *data.LcmClientRepo,
	mtlsCertRepo *data.MtlsCertificateRepo,
) *IssuerService {
	return &IssuerService{
		log:          ctx.NewLoggerHelper("lcm/service/issuer"),
		issuerRepo:   issuerRepo,
		clientRepo:   clientRepo,
		mtlsCertRepo: mtlsCertRepo,
	}
}

// getClientTenantID extracts the tenant ID from the authenticated client
// and sets it in the context for audit logging.
// The mTLS certificate CN may be the hostname, but the actual client_id is the machine-id.
// We use the mtls_certificates table to map CN -> client_id.
func (s *IssuerService) getClientTenantID(ctx context.Context) (uint32, error) {
	// Get CN from mTLS certificate (this may be hostname, not machine-id)
	certCN := client.GetClientID(ctx)
	if certCN == "" {
		return 0, lcmV1.ErrorUnauthorized("client authentication required")
	}

	// First, try to find the actual client_id by looking up the CN in mtls_certificates
	// This handles the case where CN is hostname but client_id is machine-id
	clientID := certCN // Default to CN if no mapping found
	if s.mtlsCertRepo != nil {
		actualClientID, err := s.mtlsCertRepo.GetClientIDByCommonName(ctx, certCN)
		if err != nil {
			s.log.Errorf("Failed to lookup client_id by CN: %v", err)
			// Continue with CN as client_id (backwards compatibility)
		} else if actualClientID != "" {
			clientID = actualClientID
			s.log.Debugf("Resolved CN '%s' to client_id '%s'", certCN, clientID)
		}
	}

	// First try to find client with tenant_id = 0 (platform-level clients)
	lcmClient, err := s.clientRepo.GetByTenantAndClientID(ctx, 0, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, lcmV1.ErrorInternalServerError("failed to lookup client")
	}

	if lcmClient != nil {
		// Platform-level client
		if lcmClient.TenantID != nil {
			client.SetTenantIDInPlace(ctx, *lcmClient.TenantID)
			return *lcmClient.TenantID, nil
		}
		return 0, nil
	}

	// If not found at platform level, search across all tenants by client_id
	// This is a fallback - in production you might want to limit this
	allClients, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, lcmV1.ErrorInternalServerError("failed to lookup client")
	}
	if allClients == nil {
		return 0, lcmV1.ErrorNotFound("client not registered")
	}

	if allClients.TenantID != nil {
		client.SetTenantIDInPlace(ctx, *allClients.TenantID)
		return *allClients.TenantID, nil
	}
	return 0, nil
}

// ListIssuers lists all issuers for the authenticated client's tenant
func (s *IssuerService) ListIssuers(ctx context.Context, _ *emptypb.Empty) (*lcmV1.ListIssuersResponse, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	s.log.Infof("ListIssuers: tenant_id=%d", tenantID)

	issuers, err := s.issuerRepo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	response := &lcmV1.ListIssuersResponse{
		Issuers: make([]*lcmV1.IssuerInfo, 0, len(issuers)),
	}
	for _, issuer := range issuers {
		response.Issuers = append(response.Issuers, s.issuerRepo.ToProto(issuer))
	}

	return response, nil
}

// GetIssuerInfo gets information about a specific issuer
func (s *IssuerService) GetIssuerInfo(ctx context.Context, req *lcmV1.GetIssuerInfoRequest) (*lcmV1.GetIssuerInfoResponse, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	s.log.Infof("GetIssuerInfo: name=%s, tenant_id=%d", req.GetIssuerName(), tenantID)

	issuer, err := s.issuerRepo.GetByTenantAndName(ctx, tenantID, req.GetIssuerName())
	if err != nil {
		return nil, err
	}
	if issuer == nil {
		return nil, lcmV1.ErrorNotFound("issuer '%s' not found", req.GetIssuerName())
	}

	return &lcmV1.GetIssuerInfoResponse{
		Issuer: s.issuerRepo.ToProto(issuer),
	}, nil
}

// CreateIssuer creates a new issuer for the authenticated client's tenant
func (s *IssuerService) CreateIssuer(ctx context.Context, req *lcmV1.CreateIssuerRequest) (*lcmV1.CreateIssuerResponse, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	s.log.Infof("CreateIssuer: name=%s, type=%s, tenant_id=%d", req.GetName(), req.GetType(), tenantID)

	// Validate request based on type
	switch req.GetType() {
	case "self-signed":
		if req.SelfIssuer == nil {
			return nil, lcmV1.ErrorBadRequest("self_issuer configuration required for self-signed type")
		}
	case "acme":
		if req.AcmeIssuer == nil {
			return nil, lcmV1.ErrorBadRequest("acme_issuer configuration required for acme type")
		}
		// Validate DNS provider configuration if challenge type is DNS
		if req.AcmeIssuer.ChallengeType == lcmV1.ChallengeType_DNS {
			if err := s.validateDnsProvider(req.AcmeIssuer.ProviderName, req.AcmeIssuer.ProviderConfig); err != nil {
				return nil, err
			}
		}
	default:
		return nil, lcmV1.ErrorBadRequest("invalid issuer type: %s", req.GetType())
	}

	// Check if issuer already exists
	existing, err := s.issuerRepo.GetByTenantAndName(ctx, tenantID, req.GetName())
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, lcmV1.ErrorConflict("issuer '%s' already exists", req.GetName())
	}

	// Create the issuer
	issuer, err := s.issuerRepo.Create(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}

	s.log.Infof("Created issuer: id=%d, name=%s, tenant_id=%d", issuer.ID, issuer.Name, tenantID)

	return &lcmV1.CreateIssuerResponse{
		Issuer: s.issuerRepo.ToProto(issuer),
	}, nil
}

// UpdateIssuer updates an existing issuer
func (s *IssuerService) UpdateIssuer(ctx context.Context, req *lcmV1.UpdateIssuerRequest) (*emptypb.Empty, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	s.log.Infof("UpdateIssuer: name=%s, tenant_id=%d", req.GetName(), tenantID)

	// Find the issuer
	existing, err := s.issuerRepo.GetByTenantAndName(ctx, tenantID, req.GetName())
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, lcmV1.ErrorNotFound("issuer '%s' not found", req.GetName())
	}

	// Update the issuer
	_, err = s.issuerRepo.Update(ctx, existing.ID, tenantID, req)
	if err != nil {
		return nil, err
	}

	s.log.Infof("Updated issuer: id=%d, name=%s, tenant_id=%d", existing.ID, existing.Name, tenantID)

	return &emptypb.Empty{}, nil
}

// DeleteIssuer deletes an issuer
func (s *IssuerService) DeleteIssuer(ctx context.Context, req *lcmV1.DeleteIssuerRequest) (*emptypb.Empty, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	s.log.Infof("DeleteIssuer: name=%s, tenant_id=%d", req.GetName(), tenantID)

	err = s.issuerRepo.Delete(ctx, tenantID, req.GetName())
	if err != nil {
		return nil, err
	}

	s.log.Infof("Deleted issuer: name=%s, tenant_id=%d", req.GetName(), tenantID)

	return &emptypb.Empty{}, nil
}

// ListDnsProviders lists all available DNS providers for DNS challenges
func (s *IssuerService) ListDnsProviders(_ context.Context, _ *emptypb.Empty) (*lcmV1.ListDnsProvidersResponse, error) {
	allProviders := dns.GetAllProviderInfo()

	response := &lcmV1.ListDnsProvidersResponse{
		Providers: make([]*lcmV1.DnsProviderInfo, 0, len(allProviders)),
	}

	for _, info := range allProviders {
		response.Providers = append(response.Providers, &lcmV1.DnsProviderInfo{
			Name:           info.Name,
			Description:    info.Description,
			RequiredFields: info.RequiredFields,
			OptionalFields: info.OptionalFields,
		})
	}

	return response, nil
}

// GetDnsProviderInfo gets information about a specific DNS provider
func (s *IssuerService) GetDnsProviderInfo(_ context.Context, req *lcmV1.GetDnsProviderInfoRequest) (*lcmV1.DnsProviderInfo, error) {
	info, err := dns.GetProviderInfo(req.GetName())
	if err != nil {
		return nil, lcmV1.ErrorNotFound("DNS provider '%s' not found", req.GetName())
	}

	return &lcmV1.DnsProviderInfo{
		Name:           info.Name,
		Description:    info.Description,
		RequiredFields: info.RequiredFields,
		OptionalFields: info.OptionalFields,
	}, nil
}

// validateDnsProvider validates the DNS provider configuration
func (s *IssuerService) validateDnsProvider(providerName string, config map[string]string) error {
	if providerName == "" {
		return lcmV1.ErrorBadRequest("provider_name is required for DNS challenge type")
	}

	info, err := dns.GetProviderInfo(providerName)
	if err != nil {
		return lcmV1.ErrorBadRequest("unknown DNS provider: %s. Use ListDnsProviders to see available providers", providerName)
	}

	// Check required fields
	missingFields := make([]string, 0)
	for _, field := range info.RequiredFields {
		if val, ok := config[field]; !ok || val == "" {
			missingFields = append(missingFields, field)
		}
	}

	if len(missingFields) > 0 {
		return lcmV1.ErrorBadRequest("missing required configuration fields for DNS provider '%s': %v", providerName, missingFields)
	}

	return nil
}

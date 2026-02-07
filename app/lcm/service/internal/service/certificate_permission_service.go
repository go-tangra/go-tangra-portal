package service

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/certificatepermission"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

// CertificatePermissionService implements the CertificatePermissionService gRPC service
type CertificatePermissionService struct {
	lcmV1.UnimplementedCertificatePermissionServiceServer

	log            *log.Helper
	permissionRepo *data.CertificatePermissionRepo
	clientRepo     *data.LcmClientRepo
	issuedCertRepo *data.IssuedCertificateRepo
}

// NewCertificatePermissionService creates a new CertificatePermissionService
func NewCertificatePermissionService(
	ctx *bootstrap.Context,
	permissionRepo *data.CertificatePermissionRepo,
	clientRepo *data.LcmClientRepo,
	issuedCertRepo *data.IssuedCertificateRepo,
) *CertificatePermissionService {
	return &CertificatePermissionService{
		log:            ctx.NewLoggerHelper("lcm/service/certificate-permission"),
		permissionRepo: permissionRepo,
		clientRepo:     clientRepo,
		issuedCertRepo: issuedCertRepo,
	}
}

// getClientInfo extracts the tenant ID and client ID from the authenticated client
func (s *CertificatePermissionService) getClientInfo(ctx context.Context) (uint32, string, uint32, error) {
	clientID := client.GetClientID(ctx)
	if clientID == "" {
		return 0, "", 0, lcmV1.ErrorUnauthorized("client authentication required")
	}

	lcmClient, err := s.clientRepo.GetByTenantAndClientID(ctx, 0, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, "", 0, lcmV1.ErrorInternalServerError("failed to lookup client")
	}

	if lcmClient != nil {
		var tenantID uint32
		if lcmClient.TenantID != nil {
			tenantID = *lcmClient.TenantID
		}
		return tenantID, clientID, lcmClient.ID, nil
	}

	allClients, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, "", 0, lcmV1.ErrorInternalServerError("failed to lookup client")
	}
	if allClients == nil {
		return 0, "", 0, lcmV1.ErrorNotFound("client not registered")
	}

	var tenantID uint32
	if allClients.TenantID != nil {
		tenantID = *allClients.TenantID
	}
	return tenantID, clientID, allClients.ID, nil
}

// GrantPermission grants access to a certificate to another client
func (s *CertificatePermissionService) GrantPermission(ctx context.Context, req *lcmV1.GrantPermissionRequest) (*lcmV1.GrantPermissionResponse, error) {
	tenantID, callerClientID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	s.log.Infof("GrantPermission: tenant=%d, caller=%s, cert=%s, grantee=%s, type=%v",
		tenantID, callerClientID, req.GetCertificateId(), req.GetGranteeClientId(), req.GetPermissionType())

	// Get the certificate and verify ownership
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetCertificateId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("certificate not found")
	}

	// Verify the caller owns the certificate
	if cert.ClientID != callerClientID {
		return nil, lcmV1.ErrorForbidden("only the certificate owner can grant permissions")
	}

	// Get the grantee client to verify it exists and get its numeric ID
	granteeClient, err := s.clientRepo.GetByTenantAndClientID(ctx, tenantID, req.GetGranteeClientId())
	if err != nil {
		return nil, err
	}
	if granteeClient == nil {
		return nil, lcmV1.ErrorNotFound("grantee client '%s' not found", req.GetGranteeClientId())
	}

	// Cannot grant to self
	if granteeClient.ClientID == callerClientID {
		return nil, lcmV1.ErrorBadRequest("cannot grant permission to yourself")
	}

	// Convert permission type
	permType := data.ProtoPermissionTypeToEnt(req.GetPermissionType())

	// Handle expiration
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		if t.Before(time.Now()) {
			return nil, lcmV1.ErrorBadRequest("expiration time must be in the future")
		}
		expiresAt = &t
	}

	// Create the permission
	permission, err := s.permissionRepo.Create(
		ctx,
		tenantID,
		req.GetCertificateId(),
		granteeClient.ID,
		permType,
		callerClientID,
		expiresAt,
	)
	if err != nil {
		return nil, err
	}

	return &lcmV1.GrantPermissionResponse{
		Permission: s.permissionRepo.ToProto(permission),
	}, nil
}

// RevokePermission revokes a previously granted permission
func (s *CertificatePermissionService) RevokePermission(ctx context.Context, req *lcmV1.RevokePermissionRequest) (*emptypb.Empty, error) {
	tenantID, callerClientID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	s.log.Infof("RevokePermission: tenant=%d, caller=%s, cert=%s, grantee=%s",
		tenantID, callerClientID, req.GetCertificateId(), req.GetGranteeClientId())

	// Get the certificate and verify ownership
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetCertificateId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("certificate not found")
	}

	// Verify the caller owns the certificate
	if cert.ClientID != callerClientID {
		return nil, lcmV1.ErrorForbidden("only the certificate owner can revoke permissions")
	}

	// Get the grantee client to get its numeric ID
	granteeClient, err := s.clientRepo.GetByTenantAndClientID(ctx, tenantID, req.GetGranteeClientId())
	if err != nil {
		return nil, err
	}
	if granteeClient == nil {
		return nil, lcmV1.ErrorNotFound("grantee client '%s' not found", req.GetGranteeClientId())
	}

	// Delete the permission
	err = s.permissionRepo.Delete(ctx, req.GetCertificateId(), granteeClient.ID)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListPermissions lists all permissions for a certificate (caller must be owner)
func (s *CertificatePermissionService) ListPermissions(ctx context.Context, req *lcmV1.ListPermissionsRequest) (*lcmV1.ListPermissionsResponse, error) {
	_, callerClientID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Get the certificate and verify ownership
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetCertificateId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("certificate not found")
	}

	// Verify the caller owns the certificate
	if cert.ClientID != callerClientID {
		return nil, lcmV1.ErrorForbidden("only the certificate owner can list permissions")
	}

	// List permissions
	permissions, err := s.permissionRepo.ListByCertificate(ctx, req.GetCertificateId())
	if err != nil {
		return nil, err
	}

	// Convert to proto
	var protoPermissions []*lcmV1.CertificatePermission
	for _, p := range permissions {
		protoPermissions = append(protoPermissions, s.permissionRepo.ToProto(p))
	}

	return &lcmV1.ListPermissionsResponse{
		Permissions: protoPermissions,
		Total:       uint32(len(protoPermissions)),
	}, nil
}

// ListAccessibleCertificates lists all certificates accessible to the calling client
func (s *CertificatePermissionService) ListAccessibleCertificates(ctx context.Context, req *lcmV1.ListAccessibleCertificatesRequest) (*lcmV1.ListAccessibleCertificatesResponse, error) {
	_, callerClientID, callerID, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Get all accessible certificates
	accessibleCerts, err := s.issuedCertRepo.ListAccessibleByClient(ctx, callerClientID, callerID)
	if err != nil {
		return nil, err
	}

	// Filter by permission type if specified and convert to proto
	var result []*lcmV1.AccessibleCertificate
	for _, ac := range accessibleCerts {
		// Skip if permission type filter is specified and doesn't match
		if req.PermissionType != nil && *req.PermissionType != lcmV1.PermissionType_PERMISSION_TYPE_UNSPECIFIED {
			if ac.IsOwner {
				// Owners always have FULL access
				if *req.PermissionType > lcmV1.PermissionType_PERMISSION_TYPE_FULL {
					continue
				}
			} else if ac.Permission != nil {
				permType := entPermissionTypeToProtoVal(ac.Permission.PermissionType)
				if permType < *req.PermissionType {
					continue
				}
			}
		}

		// Check expiration
		if !ac.IsOwner && ac.Permission != nil && ac.Permission.ExpiresAt != nil {
			if ac.Permission.ExpiresAt.Before(time.Now()) {
				if req.IncludeExpired == nil || !*req.IncludeExpired {
					continue
				}
			}
		}

		cert := ac.Certificate
		accessCert := &lcmV1.AccessibleCertificate{
			CertificateId: cert.ID,
			OwnerClientId: cert.ClientID,
			CommonName:    getDomainCommonName(cert.Domains),
			DnsNames:      cert.Domains,
			IssuerName:    cert.IssuerName,
		}

		if ac.IsOwner {
			accessCert.PermissionType = lcmV1.PermissionType_PERMISSION_TYPE_FULL
			accessCert.GrantedBy = cert.ClientID
			accessCert.GrantedAt = timestamppb.New(cert.CreatedAt)
		} else if ac.Permission != nil {
			accessCert.PermissionType = entPermissionTypeToProtoVal(ac.Permission.PermissionType)
			accessCert.GrantedBy = ac.Permission.GrantedBy
			accessCert.GrantedAt = timestamppb.New(ac.Permission.CreatedAt)
			if ac.Permission.ExpiresAt != nil {
				accessCert.ExpiresAt = timestamppb.New(*ac.Permission.ExpiresAt)
			}
		}

		if !cert.ExpiresAt.IsZero() {
			accessCert.CertificateExpiresAt = timestamppb.New(cert.ExpiresAt)
		}

		result = append(result, accessCert)
	}

	return &lcmV1.ListAccessibleCertificatesResponse{
		Certificates: result,
		Total:        uint32(len(result)),
	}, nil
}

// CheckPermission checks if the calling client has permission to access a certificate
func (s *CertificatePermissionService) CheckPermission(ctx context.Context, req *lcmV1.CheckPermissionRequest) (*lcmV1.CheckPermissionResponse, error) {
	tenantID, callerClientID, callerID, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Get the certificate
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetCertificateId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("certificate not found")
	}

	// Check if caller is the owner
	if cert.ClientID == callerClientID {
		return &lcmV1.CheckPermissionResponse{
			HasPermission:     true,
			IsOwner:           true,
			GrantedPermission: lcmV1.PermissionType_PERMISSION_TYPE_FULL.Enum(),
		}, nil
	}

	// Check for permission grant
	requiredType := data.ProtoPermissionTypeToEnt(req.GetRequiredPermission())
	hasPermission, permission, err := s.permissionRepo.HasPermission(ctx, req.GetCertificateId(), callerID, requiredType)
	if err != nil {
		return nil, err
	}

	if !hasPermission {
		// Try by client ID string as well (for cross-tenant scenarios)
		hasPermission, permission, err = s.permissionRepo.HasPermissionByClientID(ctx, req.GetCertificateId(), tenantID, callerClientID, requiredType)
		if err != nil {
			return nil, err
		}
	}

	resp := &lcmV1.CheckPermissionResponse{
		HasPermission: hasPermission,
		IsOwner:       false,
	}

	if hasPermission && permission != nil {
		grantedPerm := entPermissionTypeToProtoVal(permission.PermissionType)
		resp.GrantedPermission = &grantedPerm
	}

	return resp, nil
}

// getDomainCommonName returns the first domain as the common name
func getDomainCommonName(domains []string) string {
	if len(domains) > 0 {
		return domains[0]
	}
	return ""
}

// entPermissionTypeToProtoVal converts ent permission type to proto value
func entPermissionTypeToProtoVal(pt certificatepermission.PermissionType) lcmV1.PermissionType {
	switch pt {
	case certificatepermission.PermissionTypeREAD:
		return lcmV1.PermissionType_PERMISSION_TYPE_READ
	case certificatepermission.PermissionTypeDOWNLOAD:
		return lcmV1.PermissionType_PERMISSION_TYPE_DOWNLOAD
	case certificatepermission.PermissionTypeFULL:
		return lcmV1.PermissionType_PERMISSION_TYPE_FULL
	default:
		return lcmV1.PermissionType_PERMISSION_TYPE_UNSPECIFIED
	}
}

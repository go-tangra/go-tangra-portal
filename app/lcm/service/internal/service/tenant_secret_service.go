package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/tenantsecret"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

// TenantSecretService implements the TenantSecretService gRPC service
type TenantSecretService struct {
	lcmV1.UnimplementedTenantSecretServiceServer

	log              *log.Helper
	tenantSecretRepo *data.TenantSecretRepo
	clientRepo       *data.LcmClientRepo
}

// NewTenantSecretService creates a new TenantSecretService
func NewTenantSecretService(
	ctx *bootstrap.Context,
	tenantSecretRepo *data.TenantSecretRepo,
	clientRepo *data.LcmClientRepo,
) *TenantSecretService {
	return &TenantSecretService{
		log:              ctx.NewLoggerHelper("lcm/service/tenant-secret"),
		tenantSecretRepo: tenantSecretRepo,
		clientRepo:       clientRepo,
	}
}

// checkAdminAccess verifies the caller has admin access (tenant_id = 0)
func (s *TenantSecretService) checkAdminAccess(ctx context.Context) error {
	clientID := client.GetClientID(ctx)
	if clientID == "" {
		return lcmV1.ErrorUnauthorized("client authentication required")
	}

	// Get client to check tenant_id
	lcmClient, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return lcmV1.ErrorInternalServerError("failed to lookup client")
	}
	if lcmClient == nil {
		return lcmV1.ErrorNotFound("client not registered")
	}

	// Only tenant_id = 0 (platform admin) can manage tenant secrets
	if lcmClient.TenantID != nil && *lcmClient.TenantID != 0 {
		return lcmV1.ErrorForbidden("only platform admin can manage tenant secrets")
	}

	return nil
}

// CreateTenantSecret creates a new tenant secret
func (s *TenantSecretService) CreateTenantSecret(ctx context.Context, req *lcmV1.CreateTenantSecretRequest) (*lcmV1.CreateTenantSecretResponse, error) {
	s.log.Infof("CreateTenantSecret: tenant_id=%d", req.GetTenantId())

	// Check admin access
	if err := s.checkAdminAccess(ctx); err != nil {
		return nil, err
	}

	// Create the secret
	var description string
	if req.Description != nil {
		description = *req.Description
	}

	entity, err := s.tenantSecretRepo.Create(ctx, req.GetTenantId(), req.GetSecret(), description)
	if err != nil {
		return nil, err
	}

	return &lcmV1.CreateTenantSecretResponse{
		TenantSecret: s.tenantSecretRepo.ToProto(entity),
	}, nil
}

// ListTenantSecrets lists tenant secrets
func (s *TenantSecretService) ListTenantSecrets(ctx context.Context, req *lcmV1.ListTenantSecretsRequest) (*lcmV1.ListTenantSecretsResponse, error) {
	s.log.Infof("ListTenantSecrets: tenant_id=%v", req.TenantId)

	// Check admin access
	if err := s.checkAdminAccess(ctx); err != nil {
		return nil, err
	}

	var entities []*ent.TenantSecret
	var err error

	if req.TenantId != nil {
		entities, err = s.tenantSecretRepo.ListByTenantID(ctx, *req.TenantId)
	} else {
		// List all - need to implement this in repo
		entities, err = s.tenantSecretRepo.ListAll(ctx)
	}
	if err != nil {
		return nil, err
	}

	items := make([]*lcmV1.TenantSecret, 0, len(entities))
	for _, entity := range entities {
		items = append(items, s.tenantSecretRepo.ToProto(entity))
	}

	return &lcmV1.ListTenantSecretsResponse{
		Items: items,
		Total: uint64(len(items)),
	}, nil
}

// GetTenantSecret gets a tenant secret by ID
func (s *TenantSecretService) GetTenantSecret(ctx context.Context, req *lcmV1.GetTenantSecretRequest) (*lcmV1.GetTenantSecretResponse, error) {
	s.log.Infof("GetTenantSecret: id=%d", req.GetId())

	// Check admin access
	if err := s.checkAdminAccess(ctx); err != nil {
		return nil, err
	}

	entity, err := s.tenantSecretRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, lcmV1.ErrorNotFound("tenant secret not found")
	}

	return &lcmV1.GetTenantSecretResponse{
		TenantSecret: s.tenantSecretRepo.ToProto(entity),
	}, nil
}

// UpdateTenantSecret updates a tenant secret
func (s *TenantSecretService) UpdateTenantSecret(ctx context.Context, req *lcmV1.UpdateTenantSecretRequest) (*lcmV1.UpdateTenantSecretResponse, error) {
	s.log.Infof("UpdateTenantSecret: id=%d", req.GetId())

	// Check admin access
	if err := s.checkAdminAccess(ctx); err != nil {
		return nil, err
	}

	// Get existing entity
	entity, err := s.tenantSecretRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, lcmV1.ErrorNotFound("tenant secret not found")
	}

	// Update status if provided
	if req.Status != nil {
		var status tenantsecret.Status
		switch *req.Status {
		case lcmV1.TenantSecretStatus_TENANT_SECRET_STATUS_ACTIVE:
			status = tenantsecret.StatusTENANT_SECRET_STATUS_ACTIVE
		case lcmV1.TenantSecretStatus_TENANT_SECRET_STATUS_DISABLED:
			status = tenantsecret.StatusTENANT_SECRET_STATUS_DISABLED
		default:
			status = tenantsecret.StatusTENANT_SECRET_STATUS_UNSPECIFIED
		}
		entity, err = s.tenantSecretRepo.UpdateStatus(ctx, req.GetId(), status)
		if err != nil {
			return nil, err
		}
	}

	return &lcmV1.UpdateTenantSecretResponse{
		TenantSecret: s.tenantSecretRepo.ToProto(entity),
	}, nil
}

// DeleteTenantSecret deletes a tenant secret
func (s *TenantSecretService) DeleteTenantSecret(ctx context.Context, req *lcmV1.DeleteTenantSecretRequest) (*emptypb.Empty, error) {
	s.log.Infof("DeleteTenantSecret: id=%d", req.GetId())

	// Check admin access
	if err := s.checkAdminAccess(ctx); err != nil {
		return nil, err
	}

	if err := s.tenantSecretRepo.Delete(ctx, req.GetId()); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// RotateTenantSecret rotates a tenant secret
func (s *TenantSecretService) RotateTenantSecret(ctx context.Context, req *lcmV1.RotateTenantSecretRequest) (*lcmV1.RotateTenantSecretResponse, error) {
	s.log.Infof("RotateTenantSecret: id=%d", req.GetId())

	// Check admin access
	if err := s.checkAdminAccess(ctx); err != nil {
		return nil, err
	}

	disableOld := false
	if req.DisableOld != nil {
		disableOld = *req.DisableOld
	}

	newEntity, oldEntity, err := s.tenantSecretRepo.Rotate(ctx, req.GetId(), req.GetNewSecret(), disableOld)
	if err != nil {
		return nil, err
	}

	resp := &lcmV1.RotateTenantSecretResponse{
		NewSecret: s.tenantSecretRepo.ToProto(newEntity),
	}
	if oldEntity != nil {
		resp.OldSecret = s.tenantSecretRepo.ToProto(oldEntity)
	}

	return resp, nil
}

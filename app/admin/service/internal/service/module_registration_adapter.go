package service

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// CommonModuleRegistrationAdapter adapts the admin ModuleRegistrationService
// to implement the common.service.v1.ModuleRegistrationService interface.
// This allows modules that use the common proto to register with the admin service.
type CommonModuleRegistrationAdapter struct {
	commonV1.UnimplementedModuleRegistrationServiceServer
	delegate *ModuleRegistrationService
}

// NewCommonModuleRegistrationAdapter creates a new adapter.
func NewCommonModuleRegistrationAdapter(delegate *ModuleRegistrationService) *CommonModuleRegistrationAdapter {
	return &CommonModuleRegistrationAdapter{delegate: delegate}
}

// RegisterModule adapts the common RegisterModule request to the admin version.
func (a *CommonModuleRegistrationAdapter) RegisterModule(ctx context.Context, req *commonV1.RegisterModuleRequest) (*commonV1.RegisterModuleResponse, error) {
	// Convert common request to admin request
	adminReq := &adminV1.RegisterModuleRequest{
		ModuleId:        req.GetModuleId(),
		ModuleName:      req.GetModuleName(),
		Version:         req.GetVersion(),
		Description:     req.GetDescription(),
		GrpcEndpoint:    req.GetGrpcEndpoint(),
		OpenapiSpec:     req.GetOpenapiSpec(),
		ProtoDescriptor: req.GetProtoDescriptor(),
		MenusYaml:       req.GetMenusYaml(),
		AuthToken:       req.GetAuthToken(),
	}

	// Call the delegate
	adminResp, err := a.delegate.RegisterModule(ctx, adminReq)
	if err != nil {
		return nil, err
	}

	// Convert admin response to common response
	return &commonV1.RegisterModuleResponse{
		RegistrationId: adminResp.GetRegistrationId(),
		Status:         convertModuleStatus(adminResp.GetStatus()),
		Message:        adminResp.GetMessage(),
	}, nil
}

// UnregisterModule adapts the common UnregisterModule request.
func (a *CommonModuleRegistrationAdapter) UnregisterModule(ctx context.Context, req *commonV1.UnregisterModuleRequest) (*commonV1.UnregisterModuleResponse, error) {
	adminReq := &adminV1.UnregisterModuleRequest{
		ModuleId:  req.GetModuleId(),
		AuthToken: req.GetAuthToken(),
	}

	_, err := a.delegate.UnregisterModule(ctx, adminReq)
	if err != nil {
		return nil, err
	}

	return &commonV1.UnregisterModuleResponse{
		Success: true,
		Message: "Module unregistered successfully",
	}, nil
}

// Heartbeat adapts the common Heartbeat request.
func (a *CommonModuleRegistrationAdapter) Heartbeat(ctx context.Context, req *commonV1.HeartbeatRequest) (*commonV1.HeartbeatResponse, error) {
	adminReq := &adminV1.HeartbeatRequest{
		ModuleId: req.GetModuleId(),
		Health:   convertModuleHealthToAdmin(req.GetHealth()),
		Message:  req.GetMessage(),
	}

	adminResp, err := a.delegate.Heartbeat(ctx, adminReq)
	if err != nil {
		return nil, err
	}

	var nextHeartbeat *timestamppb.Timestamp
	if adminResp.GetNextHeartbeat() != nil {
		nextHeartbeat = adminResp.GetNextHeartbeat()
	}

	return &commonV1.HeartbeatResponse{
		Acknowledged:  adminResp.GetAcknowledged(),
		NextHeartbeat: nextHeartbeat,
	}, nil
}

// ListModules adapts the common ListModules request.
func (a *CommonModuleRegistrationAdapter) ListModules(ctx context.Context, req *commonV1.ListModulesRequest) (*commonV1.ListModulesResponse, error) {
	adminReq := &adminV1.ListModulesRequest{}
	if req.Status != nil {
		status := convertModuleStatusToAdmin(*req.Status)
		adminReq.Status = &status
	}
	if req.Health != nil {
		health := convertModuleHealthToAdmin(*req.Health)
		adminReq.Health = &health
	}

	adminResp, err := a.delegate.ListModules(ctx, adminReq)
	if err != nil {
		return nil, err
	}

	modules := make([]*commonV1.Module, 0, len(adminResp.GetModules()))
	for _, m := range adminResp.GetModules() {
		modules = append(modules, convertModuleToCommon(m))
	}

	return &commonV1.ListModulesResponse{
		Modules: modules,
		Total:   adminResp.GetTotal(),
	}, nil
}

// GetModule adapts the common GetModule request.
func (a *CommonModuleRegistrationAdapter) GetModule(ctx context.Context, req *commonV1.GetModuleRequest) (*commonV1.GetModuleResponse, error) {
	adminReq := &adminV1.GetModuleRequest{
		ModuleId: req.GetModuleId(),
	}

	adminResp, err := a.delegate.GetModule(ctx, adminReq)
	if err != nil {
		return nil, err
	}

	return &commonV1.GetModuleResponse{
		Module: convertModuleToCommon(adminResp),
	}, nil
}

// Helper functions for type conversions

func convertModuleStatus(status adminV1.ModuleStatus) commonV1.ModuleStatus {
	switch status {
	case adminV1.ModuleStatus_MODULE_STATUS_ACTIVE:
		return commonV1.ModuleStatus_MODULE_STATUS_ACTIVE
	case adminV1.ModuleStatus_MODULE_STATUS_INACTIVE:
		return commonV1.ModuleStatus_MODULE_STATUS_INACTIVE
	case adminV1.ModuleStatus_MODULE_STATUS_ERROR:
		return commonV1.ModuleStatus_MODULE_STATUS_ERROR
	default:
		return commonV1.ModuleStatus_MODULE_STATUS_UNSPECIFIED
	}
}

func convertModuleStatusToAdmin(status commonV1.ModuleStatus) adminV1.ModuleStatus {
	switch status {
	case commonV1.ModuleStatus_MODULE_STATUS_ACTIVE:
		return adminV1.ModuleStatus_MODULE_STATUS_ACTIVE
	case commonV1.ModuleStatus_MODULE_STATUS_INACTIVE:
		return adminV1.ModuleStatus_MODULE_STATUS_INACTIVE
	case commonV1.ModuleStatus_MODULE_STATUS_ERROR:
		return adminV1.ModuleStatus_MODULE_STATUS_ERROR
	default:
		return adminV1.ModuleStatus_MODULE_STATUS_UNSPECIFIED
	}
}

func convertModuleHealthToAdmin(health commonV1.ModuleHealth) adminV1.ModuleHealth {
	switch health {
	case commonV1.ModuleHealth_MODULE_HEALTH_HEALTHY:
		return adminV1.ModuleHealth_MODULE_HEALTH_HEALTHY
	case commonV1.ModuleHealth_MODULE_HEALTH_DEGRADED:
		return adminV1.ModuleHealth_MODULE_HEALTH_DEGRADED
	case commonV1.ModuleHealth_MODULE_HEALTH_UNHEALTHY:
		return adminV1.ModuleHealth_MODULE_HEALTH_UNHEALTHY
	default:
		return adminV1.ModuleHealth_MODULE_HEALTH_UNSPECIFIED
	}
}

func convertModuleHealth(health adminV1.ModuleHealth) commonV1.ModuleHealth {
	switch health {
	case adminV1.ModuleHealth_MODULE_HEALTH_HEALTHY:
		return commonV1.ModuleHealth_MODULE_HEALTH_HEALTHY
	case adminV1.ModuleHealth_MODULE_HEALTH_DEGRADED:
		return commonV1.ModuleHealth_MODULE_HEALTH_DEGRADED
	case adminV1.ModuleHealth_MODULE_HEALTH_UNHEALTHY:
		return commonV1.ModuleHealth_MODULE_HEALTH_UNHEALTHY
	default:
		return commonV1.ModuleHealth_MODULE_HEALTH_UNSPECIFIED
	}
}

func convertModuleToCommon(m *adminV1.Module) *commonV1.Module {
	if m == nil {
		return nil
	}
	return &commonV1.Module{
		ModuleId:       m.GetModuleId(),
		ModuleName:     m.GetModuleName(),
		Version:        m.GetVersion(),
		Description:    m.GetDescription(),
		GrpcEndpoint:   m.GetGrpcEndpoint(),
		Status:         convertModuleStatus(m.GetStatus()),
		Health:         convertModuleHealth(m.GetHealth()),
		RegisteredAt:   m.GetRegisteredAt(),
		LastHeartbeat:  m.GetLastHeartbeat(),
		RegistrationId: m.GetRegistrationId(),
		MenuCount:      m.GetMenuCount(),
		ApiCount:       m.GetApiCount(),
		RouteCount:     m.GetRouteCount(),
	}
}

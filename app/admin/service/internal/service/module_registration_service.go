package service

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
)

// ModuleRegistrationService implements the ModuleRegistrationService gRPC service.
// This service handles dynamic module registration, heartbeats, and management.
type ModuleRegistrationService struct {
	adminV1.UnimplementedModuleRegistrationServiceServer

	log                     *log.Helper
	registry                *ModuleRegistry
	openapiParser           *OpenAPIParser
	menuParser              *MenuParser
	menuInjector            *MenuInjector
	apiInjector             *APIInjector
	roleInjector            *RoleInjector
	permissionGroupInjector *PermissionGroupInjector
}

// NewModuleRegistrationService creates a new ModuleRegistrationService.
func NewModuleRegistrationService(
	ctx *bootstrap.Context,
	registry *ModuleRegistry,
	openapiParser *OpenAPIParser,
	menuParser *MenuParser,
	menuInjector *MenuInjector,
	apiInjector *APIInjector,
	roleInjector *RoleInjector,
	permissionGroupInjector *PermissionGroupInjector,
) *ModuleRegistrationService {
	return &ModuleRegistrationService{
		log:                     ctx.NewLoggerHelper("module-registration-service/admin-service"),
		registry:                registry,
		openapiParser:           openapiParser,
		menuParser:              menuParser,
		menuInjector:            menuInjector,
		apiInjector:             apiInjector,
		roleInjector:            roleInjector,
		permissionGroupInjector: permissionGroupInjector,
	}
}

// RegisterModule handles module registration requests.
// This is called by modules on startup to register themselves with the admin gateway.
func (s *ModuleRegistrationService) RegisterModule(ctx context.Context, req *adminV1.RegisterModuleRequest) (*adminV1.RegisterModuleResponse, error) {
	s.log.Infof("Received registration request from module: %s", req.GetModuleId())

	// Validate required fields
	if req.GetModuleId() == "" {
		return nil, adminV1.ErrorBadRequest("module_id is required")
	}
	if req.GetModuleName() == "" {
		return nil, adminV1.ErrorBadRequest("module_name is required")
	}
	if req.GetGrpcEndpoint() == "" {
		return nil, adminV1.ErrorBadRequest("grpc_endpoint is required")
	}

	// TODO: Validate auth_token when authentication is implemented

	var parsedSpec *ParsedSpec
	var menuCount, apiCount, routeCount int32

	// Parse OpenAPI spec for routing and API extraction (menus are now separate)
	if len(req.GetOpenapiSpec()) > 0 {
		var err error
		parsedSpec, err = s.openapiParser.Parse(req.GetOpenapiSpec())
		if err != nil {
			s.log.Warnf("Failed to parse OpenAPI spec for module %s: %v", req.GetModuleId(), err)
			// Continue without OpenAPI - module can still be registered
		} else {
			routeCount = parsedSpec.RouteCount
		}
	}

	// Parse module YAML file (menus, roles, permission_groups)
	var menusFile *MenusFile
	if len(req.GetMenusYaml()) > 0 {
		var err error
		menusFile, err = s.menuParser.Parse(req.GetMenusYaml())
		if err != nil {
			s.log.Warnf("Failed to parse menus.yaml for module %s: %v", req.GetModuleId(), err)
			// Continue without menus - module can still be registered
		}
	}

	// Register the module in the registry first (persists to database)
	registeredModule, err := s.registry.Register(ctx, req)
	if err != nil {
		s.log.Errorf("Failed to register module %s: %v", req.GetModuleId(), err)
		return nil, adminV1.ErrorInternalServerError("failed to register module")
	}

	// Inject menus from menus.yaml (stored in-memory, not in database)
	if menusFile != nil && len(menusFile.Menus) > 0 {
		injectedMenus, err := s.menuInjector.InjectMenus(req.GetModuleId(), menusFile.Menus)
		if err != nil {
			s.log.Errorf("Failed to store menus for module %s: %v", req.GetModuleId(), err)
		} else {
			menuCount = int32(len(injectedMenus))
		}
	}

	// Inject permission groups first (permissions must exist before roles can reference them)
	if menusFile != nil && len(menusFile.PermissionGroups) > 0 {
		_, err := s.permissionGroupInjector.InjectPermissionGroups(ctx, req.GetModuleId(), menusFile.PermissionGroups)
		if err != nil {
			s.log.Errorf("Failed to inject permission groups for module %s: %v", req.GetModuleId(), err)
		}
	}

	// Inject roles (after permissions exist)
	if menusFile != nil && len(menusFile.Roles) > 0 {
		_, err := s.roleInjector.InjectRoles(ctx, req.GetModuleId(), menusFile.Roles)
		if err != nil {
			s.log.Errorf("Failed to inject roles for module %s: %v", req.GetModuleId(), err)
		}
	}

	// Inject APIs from OpenAPI spec
	if parsedSpec != nil && len(parsedSpec.APIs) > 0 {
		injectedAPIs, err := s.apiInjector.InjectAPIs(ctx, req.GetModuleId(), parsedSpec.APIs)
		if err != nil {
			s.log.Errorf("Failed to inject APIs for module %s: %v", req.GetModuleId(), err)
		} else {
			apiCount = int32(len(injectedAPIs))
		}
	}

	// Update counts in the database
	if menuCount > 0 || apiCount > 0 || routeCount > 0 {
		if err := s.registry.UpdateCounts(ctx, req.GetModuleId(), menuCount, apiCount, routeCount); err != nil {
			s.log.Warnf("Failed to update counts for module %s: %v", req.GetModuleId(), err)
		}
	}

	s.log.Infof("Successfully registered module: %s (menus=%d, apis=%d, routes=%d)",
		req.GetModuleId(), menuCount, apiCount, routeCount)

	return &adminV1.RegisterModuleResponse{
		RegistrationId: registeredModule.RegistrationID,
		Status:         registeredModule.Status,
		Message:        "Module registered successfully",
	}, nil
}

// UnregisterModule handles module unregistration requests.
// This is called by modules on graceful shutdown.
func (s *ModuleRegistrationService) UnregisterModule(ctx context.Context, req *adminV1.UnregisterModuleRequest) (*emptypb.Empty, error) {
	s.log.Infof("Received unregistration request for module: %s", req.GetModuleId())

	if req.GetModuleId() == "" {
		return nil, adminV1.ErrorBadRequest("module_id is required")
	}

	// TODO: Validate auth_token when authentication is implemented

	// Remove menus belonging to this module (from memory)
	deletedMenus, err := s.menuInjector.RemoveModuleMenus(req.GetModuleId())
	if err != nil {
		s.log.Warnf("Failed to remove menus for module %s: %v", req.GetModuleId(), err)
	}

	// Remove APIs belonging to this module
	deletedAPIs, err := s.apiInjector.RemoveModuleAPIs(ctx, req.GetModuleId())
	if err != nil {
		s.log.Warnf("Failed to remove APIs for module %s: %v", req.GetModuleId(), err)
	}

	// Note: We intentionally do NOT remove roles and permission groups on unregistration.
	// These are persistent data that users may have already assigned to their users.
	// Removing them would break existing access patterns. They will be updated
	// when the module re-registers.

	// Unregister from the registry (removes from database)
	if err := s.registry.Unregister(ctx, req.GetModuleId()); err != nil {
		s.log.Errorf("Failed to unregister module %s: %v", req.GetModuleId(), err)
		return nil, err
	}

	s.log.Infof("Successfully unregistered module: %s (removed %d menus, %d apis)",
		req.GetModuleId(), deletedMenus, deletedAPIs)

	return &emptypb.Empty{}, nil
}

// Heartbeat handles module heartbeat requests.
// This is called periodically by modules to indicate they are alive.
func (s *ModuleRegistrationService) Heartbeat(ctx context.Context, req *adminV1.HeartbeatRequest) (*adminV1.HeartbeatResponse, error) {
	if req.GetModuleId() == "" {
		return nil, adminV1.ErrorBadRequest("module_id is required")
	}

	// Update heartbeat in registry
	if err := s.registry.UpdateHealth(ctx, req.GetModuleId(), req.GetHealth(), req.GetMessage()); err != nil {
		s.log.Errorf("Failed to update heartbeat for module %s: %v", req.GetModuleId(), err)
		return &adminV1.HeartbeatResponse{
			Acknowledged: false,
		}, nil
	}

	// Suggest next heartbeat in 30 seconds
	nextHeartbeat := time.Now().Add(30 * time.Second)

	return &adminV1.HeartbeatResponse{
		Acknowledged:  true,
		NextHeartbeat: timestamppb.New(nextHeartbeat),
	}, nil
}

// ListModules returns a list of all registered modules.
func (s *ModuleRegistrationService) ListModules(ctx context.Context, req *adminV1.ListModulesRequest) (*adminV1.ListModulesResponse, error) {
	var status *adminV1.ModuleStatus
	var health *adminV1.ModuleHealth

	if req.Status != nil {
		status = req.Status
	}
	if req.Health != nil {
		health = req.Health
	}

	modules, err := s.registry.ListFromDB(ctx, status, health)
	if err != nil {
		return nil, err
	}

	protoModules := make([]*adminV1.Module, 0, len(modules))
	for _, mod := range modules {
		protoModules = append(protoModules, RegisteredModuleToProto(mod))
	}

	return &adminV1.ListModulesResponse{
		Modules: protoModules,
		Total:   int32(len(protoModules)),
	}, nil
}

// GetModule returns details of a specific module.
func (s *ModuleRegistrationService) GetModule(ctx context.Context, req *adminV1.GetModuleRequest) (*adminV1.Module, error) {
	if req.GetModuleId() == "" {
		return nil, adminV1.ErrorBadRequest("module_id is required")
	}

	// Try cache first
	mod, found := s.registry.Get(req.GetModuleId())
	if found {
		return RegisteredModuleToProto(mod), nil
	}

	// Fall back to database
	mod, err := s.registry.GetFromDB(ctx, req.GetModuleId())
	if err != nil {
		return nil, err
	}

	return RegisteredModuleToProto(mod), nil
}

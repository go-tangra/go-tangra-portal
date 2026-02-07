package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/module"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
)

// ModuleRepo handles database operations for dynamic module registration.
type ModuleRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewModuleRepo creates a new ModuleRepo.
func NewModuleRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *ModuleRepo {
	return &ModuleRepo{
		log:       ctx.NewLoggerHelper("module/repo/admin-service"),
		entClient: entClient,
	}
}

// GetByModuleID retrieves a module by its unique module_id.
func (r *ModuleRepo) GetByModuleID(ctx context.Context, moduleID string) (*ent.Module, error) {
	entity, err := r.entClient.Client().Module.Query().
		Where(module.ModuleIDEQ(moduleID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, adminV1.ErrorModuleNotFound("module not found: %s", moduleID)
		}
		r.log.Errorf("query module by id failed: %s", err.Error())
		return nil, adminV1.ErrorInternalServerError("query module failed")
	}
	return entity, nil
}

// Exists checks if a module with the given module_id exists.
func (r *ModuleRepo) Exists(ctx context.Context, moduleID string) (bool, error) {
	exist, err := r.entClient.Client().Module.Query().
		Where(module.ModuleIDEQ(moduleID)).
		Exist(ctx)
	if err != nil {
		r.log.Errorf("check module exists failed: %s", err.Error())
		return false, adminV1.ErrorInternalServerError("check module exists failed")
	}
	return exist, nil
}

// ListActive returns all modules with active status.
func (r *ModuleRepo) ListActive(ctx context.Context) ([]*ent.Module, error) {
	entities, err := r.entClient.Client().Module.Query().
		Where(module.StatusEQ(int32(adminV1.ModuleStatus_MODULE_STATUS_ACTIVE))).
		All(ctx)
	if err != nil {
		r.log.Errorf("list active modules failed: %s", err.Error())
		return nil, adminV1.ErrorInternalServerError("list active modules failed")
	}
	return entities, nil
}

// ListAll returns all modules, optionally filtered by status and health.
func (r *ModuleRepo) ListAll(ctx context.Context, status *adminV1.ModuleStatus, health *adminV1.ModuleHealth) ([]*ent.Module, error) {
	builder := r.entClient.Client().Module.Query()

	if status != nil {
		builder = builder.Where(module.StatusEQ(int32(*status)))
	}
	if health != nil {
		builder = builder.Where(module.HealthEQ(int32(*health)))
	}

	entities, err := builder.Order(ent.Asc(module.FieldCreatedAt)).All(ctx)
	if err != nil {
		r.log.Errorf("list modules failed: %s", err.Error())
		return nil, adminV1.ErrorInternalServerError("list modules failed")
	}
	return entities, nil
}

// Create creates a new module registration.
func (r *ModuleRepo) Create(ctx context.Context, req *adminV1.RegisterModuleRequest) (*ent.Module, error) {
	now := time.Now()
	registrationID := uuid.New().String()

	builder := r.entClient.Client().Module.Create().
		SetModuleID(req.GetModuleId()).
		SetModuleName(req.GetModuleName()).
		SetVersion(req.GetVersion()).
		SetGrpcEndpoint(req.GetGrpcEndpoint()).
		SetStatus(int32(adminV1.ModuleStatus_MODULE_STATUS_ACTIVE)).
		SetHealth(int32(adminV1.ModuleHealth_MODULE_HEALTH_HEALTHY)).
		SetRegistrationID(registrationID).
		SetRegisteredAt(now).
		SetLastHeartbeat(now).
		SetCreatedAt(now)

	if req.GetDescription() != "" {
		builder.SetDescription(req.GetDescription())
	}
	if len(req.GetOpenapiSpec()) > 0 {
		builder.SetOpenapiSpec(req.GetOpenapiSpec())
	}
	if len(req.GetProtoDescriptor()) > 0 {
		builder.SetProtoDescriptor(req.GetProtoDescriptor())
	}
	if len(req.GetMenusYaml()) > 0 {
		builder.SetMenusYaml(req.GetMenusYaml())
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create module failed: %s", err.Error())
		return nil, adminV1.ErrorInternalServerError("create module failed")
	}

	return entity, nil
}

// Update updates an existing module registration.
func (r *ModuleRepo) Update(ctx context.Context, moduleID string, req *adminV1.RegisterModuleRequest) (*ent.Module, error) {
	now := time.Now()
	registrationID := uuid.New().String()

	builder := r.entClient.Client().Module.Update().
		Where(module.ModuleIDEQ(moduleID)).
		SetModuleName(req.GetModuleName()).
		SetVersion(req.GetVersion()).
		SetGrpcEndpoint(req.GetGrpcEndpoint()).
		SetStatus(int32(adminV1.ModuleStatus_MODULE_STATUS_ACTIVE)).
		SetHealth(int32(adminV1.ModuleHealth_MODULE_HEALTH_HEALTHY)).
		SetRegistrationID(registrationID).
		SetRegisteredAt(now).
		SetLastHeartbeat(now).
		SetUpdatedAt(now)

	if req.GetDescription() != "" {
		builder.SetDescription(req.GetDescription())
	} else {
		builder.ClearDescription()
	}
	if len(req.GetOpenapiSpec()) > 0 {
		builder.SetOpenapiSpec(req.GetOpenapiSpec())
	} else {
		builder.ClearOpenapiSpec()
	}
	if len(req.GetProtoDescriptor()) > 0 {
		builder.SetProtoDescriptor(req.GetProtoDescriptor())
	} else {
		builder.ClearProtoDescriptor()
	}
	if len(req.GetMenusYaml()) > 0 {
		builder.SetMenusYaml(req.GetMenusYaml())
	} else {
		builder.ClearMenusYaml()
	}

	_, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("update module failed: %s", err.Error())
		return nil, adminV1.ErrorInternalServerError("update module failed")
	}

	// Fetch the updated entity
	return r.GetByModuleID(ctx, moduleID)
}

// UpdateStatus updates the status of a module.
func (r *ModuleRepo) UpdateStatus(ctx context.Context, moduleID string, status adminV1.ModuleStatus) error {
	_, err := r.entClient.Client().Module.Update().
		Where(module.ModuleIDEQ(moduleID)).
		SetStatus(int32(status)).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("update module status failed: %s", err.Error())
		return adminV1.ErrorInternalServerError("update module status failed")
	}
	return nil
}

// UpdateHealth updates the health status of a module.
func (r *ModuleRepo) UpdateHealth(ctx context.Context, moduleID string, health adminV1.ModuleHealth) error {
	_, err := r.entClient.Client().Module.Update().
		Where(module.ModuleIDEQ(moduleID)).
		SetHealth(int32(health)).
		SetLastHeartbeat(time.Now()).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("update module health failed: %s", err.Error())
		return adminV1.ErrorInternalServerError("update module health failed")
	}
	return nil
}

// UpdateHeartbeat updates the last heartbeat time of a module.
func (r *ModuleRepo) UpdateHeartbeat(ctx context.Context, moduleID string, health adminV1.ModuleHealth, message string) error {
	builder := r.entClient.Client().Module.Update().
		Where(module.ModuleIDEQ(moduleID)).
		SetHealth(int32(health)).
		SetLastHeartbeat(time.Now()).
		SetUpdatedAt(time.Now())

	_, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("update module heartbeat failed: %s", err.Error())
		return adminV1.ErrorInternalServerError("update module heartbeat failed")
	}
	return nil
}

// UpdateCounts updates the menu, API, and route counts for a module.
func (r *ModuleRepo) UpdateCounts(ctx context.Context, moduleID string, menuCount, apiCount, routeCount int32) error {
	_, err := r.entClient.Client().Module.Update().
		Where(module.ModuleIDEQ(moduleID)).
		SetMenuCount(menuCount).
		SetAPICount(apiCount).
		SetRouteCount(routeCount).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("update module counts failed: %s", err.Error())
		return adminV1.ErrorInternalServerError("update module counts failed")
	}
	return nil
}

// Delete deletes a module by its module_id.
func (r *ModuleRepo) Delete(ctx context.Context, moduleID string) error {
	_, err := r.entClient.Client().Module.Delete().
		Where(module.ModuleIDEQ(moduleID)).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete module failed: %s", err.Error())
		return adminV1.ErrorInternalServerError("delete module failed")
	}
	return nil
}

// FindStaleModules finds modules that haven't sent a heartbeat within the given duration.
func (r *ModuleRepo) FindStaleModules(ctx context.Context, timeout time.Duration) ([]*ent.Module, error) {
	threshold := time.Now().Add(-timeout)

	entities, err := r.entClient.Client().Module.Query().
		Where(
			module.StatusEQ(int32(adminV1.ModuleStatus_MODULE_STATUS_ACTIVE)),
			module.LastHeartbeatLT(threshold),
		).
		All(ctx)
	if err != nil {
		r.log.Errorf("find stale modules failed: %s", err.Error())
		return nil, adminV1.ErrorInternalServerError("find stale modules failed")
	}
	return entities, nil
}

// MarkModulesUnhealthy marks modules as unhealthy based on stale heartbeat.
func (r *ModuleRepo) MarkModulesUnhealthy(ctx context.Context, timeout time.Duration) (int, error) {
	threshold := time.Now().Add(-timeout)

	count, err := r.entClient.Client().Module.Update().
		Where(
			module.StatusEQ(int32(adminV1.ModuleStatus_MODULE_STATUS_ACTIVE)),
			module.HealthNEQ(int32(adminV1.ModuleHealth_MODULE_HEALTH_UNHEALTHY)),
			module.LastHeartbeatLT(threshold),
		).
		SetHealth(int32(adminV1.ModuleHealth_MODULE_HEALTH_UNHEALTHY)).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("mark modules unhealthy failed: %s", err.Error())
		return 0, adminV1.ErrorInternalServerError("mark modules unhealthy failed")
	}
	return count, nil
}

// EntityToProto converts an Ent Module entity to proto Module.
func (r *ModuleRepo) EntityToProto(entity *ent.Module) *adminV1.Module {
	if entity == nil {
		return nil
	}

	mod := &adminV1.Module{
		ModuleId:     entity.ModuleID,
		ModuleName:   entity.ModuleName,
		Version:      entity.Version,
		GrpcEndpoint: entity.GrpcEndpoint,
		Status:       adminV1.ModuleStatus(entity.Status),
		Health:       adminV1.ModuleHealth(entity.Health),
		MenuCount:    entity.MenuCount,
		ApiCount:     entity.APICount,
		RouteCount:   entity.RouteCount,
	}

	if entity.Description != nil {
		mod.Description = *entity.Description
	}
	if entity.RegistrationID != nil {
		mod.RegistrationId = *entity.RegistrationID
	}
	if entity.RegisteredAt != nil {
		mod.RegisteredAt = timestampFromTime(*entity.RegisteredAt)
	}
	if entity.LastHeartbeat != nil {
		mod.LastHeartbeat = timestampFromTime(*entity.LastHeartbeat)
	}

	return mod
}

// EntitiesToProtos converts multiple Ent Module entities to proto Modules.
func (r *ModuleRepo) EntitiesToProtos(entities []*ent.Module) []*adminV1.Module {
	protos := make([]*adminV1.Module, 0, len(entities))
	for _, entity := range entities {
		protos = append(protos, r.EntityToProto(entity))
	}
	return protos
}

// timestampFromTime converts time.Time to protobuf Timestamp.
func timestampFromTime(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}

package service

import (
	"context"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
)

// RegisteredModule represents a module that has been registered with the gateway.
// This is the in-memory representation used for routing and management.
type RegisteredModule struct {
	ModuleID       string
	ModuleName     string
	Version        string
	Description    string
	GrpcEndpoint   string
	Status         adminV1.ModuleStatus
	Health         adminV1.ModuleHealth
	RegistrationID string
	RegisteredAt   time.Time
	LastHeartbeat  time.Time

	// Parsed specs (populated by parser components)
	OpenapiSpec     []byte
	ProtoDescriptor []byte
	MenusYaml       []byte

	// Dynamic menus parsed from menus.yaml (recovered from DB on restart)
	Menus []*ParsedMenu

	// Dashboard widgets parsed from menus.yaml
	Widgets []*ParsedWidget

	// Counts
	MenuCount  int32
	APICount   int32
	RouteCount int32
}

// ModuleRegistryEvent represents events emitted by the registry.
type ModuleRegistryEvent struct {
	Type   ModuleEventType
	Module *RegisteredModule
}

// ModuleEventType represents the type of registry event.
type ModuleEventType int

const (
	ModuleEventRegistered ModuleEventType = iota
	ModuleEventUnregistered
	ModuleEventUpdated
	ModuleEventHealthChanged
)

// ModuleEventHandler is a callback function for module events.
type ModuleEventHandler func(event ModuleRegistryEvent)

// ModuleRegistry manages the registry of dynamic modules.
// It maintains an in-memory cache of active modules and persists them to the database.
type ModuleRegistry struct {
	log           *log.Helper
	moduleRepo    *data.ModuleRepo
	openapiParser *OpenAPIParser
	menuParser    *MenuParser

	// In-memory cache of registered modules (module_id -> *RegisteredModule)
	modules sync.Map

	// Event handlers for module changes
	eventHandlers []ModuleEventHandler
	handlersMu    sync.RWMutex
}

// NewModuleRegistry creates a new ModuleRegistry and loads active modules from the database.
func NewModuleRegistry(ctx *bootstrap.Context, moduleRepo *data.ModuleRepo, openapiParser *OpenAPIParser, menuParser *MenuParser) *ModuleRegistry {
	registry := &ModuleRegistry{
		log:           ctx.NewLoggerHelper("module-registry/admin-service"),
		moduleRepo:    moduleRepo,
		openapiParser: openapiParser,
		menuParser:    menuParser,
		eventHandlers: make([]ModuleEventHandler, 0),
	}

	// Load existing modules from database on startup
	if err := registry.LoadFromDatabase(context.Background()); err != nil {
		registry.log.Errorf("Failed to load modules from database during startup: %v", err)
	}

	return registry
}

// LoadFromDatabase loads all active modules from the database into the in-memory cache.
// This should be called during startup.
func (r *ModuleRegistry) LoadFromDatabase(ctx context.Context) error {
	entities, err := r.moduleRepo.ListActive(ctx)
	if err != nil {
		return err
	}

	for _, entity := range entities {
		mod := r.entityToRegistered(entity)

		// Try to recover menus and widgets from stored menus_yaml first (preferred)
		if len(mod.MenusYaml) > 0 && r.menuParser != nil {
			menusFile, err := r.menuParser.Parse(mod.MenusYaml)
			if err != nil {
				r.log.Warnf("Failed to parse stored menus.yaml for module %s during startup: %v", mod.ModuleID, err)
			} else {
				if len(menusFile.Menus) > 0 {
					mod.Menus = menusFile.Menus
					r.log.Infof("Loaded %d menus for module %s from stored menus.yaml", len(menusFile.Menus), mod.ModuleID)
				}
				if len(menusFile.DashboardWidgets) > 0 {
					mod.Widgets = menusFile.DashboardWidgets
					r.log.Infof("Loaded %d dashboard widgets for module %s from stored menus.yaml", len(menusFile.DashboardWidgets), mod.ModuleID)
				}
			}
		}

		// Fallback: try to recover menus from OpenAPI spec (legacy)
		if len(mod.Menus) == 0 && len(mod.OpenapiSpec) > 0 && r.openapiParser != nil {
			parsedSpec, err := r.openapiParser.Parse(mod.OpenapiSpec)
			if err != nil {
				r.log.Warnf("Failed to parse OpenAPI spec for module %s during startup: %v", mod.ModuleID, err)
			} else if len(parsedSpec.Menus) > 0 {
				mod.Menus = parsedSpec.Menus
				r.log.Infof("Loaded %d menus for module %s from stored OpenAPI spec (fallback)", len(parsedSpec.Menus), mod.ModuleID)
			}
		}

		r.modules.Store(mod.ModuleID, mod)
		r.log.Infof("Loaded module from database: %s (%s)", mod.ModuleID, mod.ModuleName)
	}

	r.log.Infof("Loaded %d active modules from database", len(entities))
	return nil
}

// Register registers a new module or updates an existing one.
// This is called when a module calls the RegisterModule RPC.
func (r *ModuleRegistry) Register(ctx context.Context, req *adminV1.RegisterModuleRequest) (*RegisteredModule, error) {
	// Check if module already exists
	exists, err := r.moduleRepo.Exists(ctx, req.GetModuleId())
	if err != nil {
		return nil, err
	}

	var entity *ent.Module
	if exists {
		// Update existing module
		entity, err = r.moduleRepo.Update(ctx, req.GetModuleId(), req)
		if err != nil {
			return nil, err
		}
		r.log.Infof("Updated existing module: %s", req.GetModuleId())
	} else {
		// Create new module
		entity, err = r.moduleRepo.Create(ctx, req)
		if err != nil {
			return nil, err
		}
		r.log.Infof("Registered new module: %s", req.GetModuleId())
	}

	// Convert to registered module and store in cache
	mod := r.entityToRegistered(entity)
	r.modules.Store(mod.ModuleID, mod)

	// Emit event
	eventType := ModuleEventRegistered
	if exists {
		eventType = ModuleEventUpdated
	}
	r.emitEvent(ModuleRegistryEvent{Type: eventType, Module: mod})

	return mod, nil
}

// Unregister removes a module from the registry.
// This is called when a module calls the UnregisterModule RPC.
func (r *ModuleRegistry) Unregister(ctx context.Context, moduleID string) error {
	// Get module before removing (for event)
	mod, exists := r.Get(moduleID)
	if !exists {
		r.log.Warnf("Attempted to unregister non-existent module: %s", moduleID)
		return adminV1.ErrorModuleNotFound("module not found: %s", moduleID)
	}

	// Remove from database
	if err := r.moduleRepo.Delete(ctx, moduleID); err != nil {
		return err
	}

	// Remove from cache
	r.modules.Delete(moduleID)

	r.log.Infof("Unregistered module: %s", moduleID)

	// Emit event
	r.emitEvent(ModuleRegistryEvent{Type: ModuleEventUnregistered, Module: mod})

	return nil
}

// UpdateHealth updates the health status of a module.
// This is called when a module sends a heartbeat.
func (r *ModuleRegistry) UpdateHealth(ctx context.Context, moduleID string, health adminV1.ModuleHealth, message string) error {
	// Update in database
	if err := r.moduleRepo.UpdateHeartbeat(ctx, moduleID, health, message); err != nil {
		return err
	}

	// Update in cache
	if val, ok := r.modules.Load(moduleID); ok {
		mod := val.(*RegisteredModule)
		oldHealth := mod.Health
		mod.Health = health
		mod.LastHeartbeat = time.Now()

		// Emit event if health changed
		if oldHealth != health {
			r.emitEvent(ModuleRegistryEvent{Type: ModuleEventHealthChanged, Module: mod})
		}
	}

	return nil
}

// Get returns a module by its ID.
func (r *ModuleRegistry) Get(moduleID string) (*RegisteredModule, bool) {
	if val, ok := r.modules.Load(moduleID); ok {
		return val.(*RegisteredModule), true
	}
	return nil, false
}

// GetFromDB returns a module from the database (not cache).
func (r *ModuleRegistry) GetFromDB(ctx context.Context, moduleID string) (*RegisteredModule, error) {
	entity, err := r.moduleRepo.GetByModuleID(ctx, moduleID)
	if err != nil {
		return nil, err
	}
	return r.entityToRegistered(entity), nil
}

// List returns all registered modules.
func (r *ModuleRegistry) List() []*RegisteredModule {
	modules := make([]*RegisteredModule, 0)
	r.modules.Range(func(key, value interface{}) bool {
		modules = append(modules, value.(*RegisteredModule))
		return true
	})
	return modules
}

// ListFromDB returns all modules from the database, optionally filtered.
func (r *ModuleRegistry) ListFromDB(ctx context.Context, status *adminV1.ModuleStatus, health *adminV1.ModuleHealth) ([]*RegisteredModule, error) {
	entities, err := r.moduleRepo.ListAll(ctx, status, health)
	if err != nil {
		return nil, err
	}

	modules := make([]*RegisteredModule, 0, len(entities))
	for _, entity := range entities {
		modules = append(modules, r.entityToRegistered(entity))
	}
	return modules, nil
}

// Count returns the number of registered modules.
func (r *ModuleRegistry) Count() int {
	count := 0
	r.modules.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// GetAllDynamicMenus returns all menus from healthy registered modules.
// These menus are kept in-memory and not persisted to the database.
func (r *ModuleRegistry) GetAllDynamicMenus() []*ParsedMenu {
	var allMenus []*ParsedMenu
	r.modules.Range(func(key, value interface{}) bool {
		mod := value.(*RegisteredModule)
		// Only include menus from healthy modules
		if mod.Health == adminV1.ModuleHealth_MODULE_HEALTH_HEALTHY && len(mod.Menus) > 0 {
			allMenus = append(allMenus, mod.Menus...)
		}
		return true
	})
	return allMenus
}

// SetModuleMenus stores the parsed menus for a module.
func (r *ModuleRegistry) SetModuleMenus(moduleID string, menus []*ParsedMenu) {
	if val, ok := r.modules.Load(moduleID); ok {
		mod := val.(*RegisteredModule)
		mod.Menus = menus
		mod.MenuCount = int32(len(menus))
	}
}

// SetModuleWidgets stores the parsed dashboard widgets for a module.
func (r *ModuleRegistry) SetModuleWidgets(moduleID string, widgets []*ParsedWidget) {
	if val, ok := r.modules.Load(moduleID); ok {
		mod := val.(*RegisteredModule)
		mod.Widgets = widgets
	}
}

// GetAllDashboardWidgets returns all dashboard widgets from healthy registered modules.
func (r *ModuleRegistry) GetAllDashboardWidgets() []*ParsedWidget {
	var allWidgets []*ParsedWidget
	r.modules.Range(func(key, value interface{}) bool {
		mod := value.(*RegisteredModule)
		if mod.Health == adminV1.ModuleHealth_MODULE_HEALTH_HEALTHY && len(mod.Widgets) > 0 {
			allWidgets = append(allWidgets, mod.Widgets...)
		}
		return true
	})
	return allWidgets
}

// UpdateCounts updates the menu, API, and route counts for a module.
func (r *ModuleRegistry) UpdateCounts(ctx context.Context, moduleID string, menuCount, apiCount, routeCount int32) error {
	if err := r.moduleRepo.UpdateCounts(ctx, moduleID, menuCount, apiCount, routeCount); err != nil {
		return err
	}

	// Update in cache
	if val, ok := r.modules.Load(moduleID); ok {
		mod := val.(*RegisteredModule)
		mod.MenuCount = menuCount
		mod.APICount = apiCount
		mod.RouteCount = routeCount
	}

	return nil
}

// OnEvent registers a handler for module events.
func (r *ModuleRegistry) OnEvent(handler ModuleEventHandler) {
	r.handlersMu.Lock()
	defer r.handlersMu.Unlock()
	r.eventHandlers = append(r.eventHandlers, handler)
}

// emitEvent sends an event to all registered handlers.
func (r *ModuleRegistry) emitEvent(event ModuleRegistryEvent) {
	r.handlersMu.RLock()
	handlers := make([]ModuleEventHandler, len(r.eventHandlers))
	copy(handlers, r.eventHandlers)
	r.handlersMu.RUnlock()

	for _, handler := range handlers {
		// Call handlers asynchronously to avoid blocking
		go handler(event)
	}
}

// MarkStaleModulesUnhealthy marks modules as unhealthy if they haven't sent a heartbeat recently.
// This should be called periodically by a background job.
func (r *ModuleRegistry) MarkStaleModulesUnhealthy(ctx context.Context, timeout time.Duration) (int, error) {
	count, err := r.moduleRepo.MarkModulesUnhealthy(ctx, timeout)
	if err != nil {
		return 0, err
	}

	if count > 0 {
		// Reload affected modules from database to update cache
		staleModules, _ := r.moduleRepo.FindStaleModules(ctx, timeout)
		for _, entity := range staleModules {
			if val, ok := r.modules.Load(entity.ModuleID); ok {
				mod := val.(*RegisteredModule)
				mod.Health = adminV1.ModuleHealth_MODULE_HEALTH_UNHEALTHY
				r.emitEvent(ModuleRegistryEvent{Type: ModuleEventHealthChanged, Module: mod})
			}
		}
		r.log.Warnf("Marked %d stale modules as unhealthy", count)
	}

	return count, nil
}

// entityToRegistered converts an ent.Module entity to a RegisteredModule.
func (r *ModuleRegistry) entityToRegistered(entity *ent.Module) *RegisteredModule {
	mod := &RegisteredModule{
		ModuleID:     entity.ModuleID,
		ModuleName:   entity.ModuleName,
		Version:      entity.Version,
		GrpcEndpoint: entity.GrpcEndpoint,
		Status:       adminV1.ModuleStatus(entity.Status),
		Health:       adminV1.ModuleHealth(entity.Health),
		MenuCount:    entity.MenuCount,
		APICount:     entity.APICount,
		RouteCount:   entity.RouteCount,
	}

	if entity.Description != nil {
		mod.Description = *entity.Description
	}
	if entity.RegistrationID != nil {
		mod.RegistrationID = *entity.RegistrationID
	}
	if entity.RegisteredAt != nil {
		mod.RegisteredAt = *entity.RegisteredAt
	}
	if entity.LastHeartbeat != nil {
		mod.LastHeartbeat = *entity.LastHeartbeat
	}
	if entity.OpenapiSpec != nil {
		mod.OpenapiSpec = *entity.OpenapiSpec
	}
	if entity.ProtoDescriptor != nil {
		mod.ProtoDescriptor = *entity.ProtoDescriptor
	}
	if entity.MenusYaml != nil {
		mod.MenusYaml = *entity.MenusYaml
	}

	return mod
}

// RegisteredModuleToProto converts a RegisteredModule to a proto Module.
func RegisteredModuleToProto(mod *RegisteredModule) *adminV1.Module {
	if mod == nil {
		return nil
	}

	protoMod := &adminV1.Module{
		ModuleId:       mod.ModuleID,
		ModuleName:     mod.ModuleName,
		Version:        mod.Version,
		Description:    mod.Description,
		GrpcEndpoint:   mod.GrpcEndpoint,
		Status:         mod.Status,
		Health:         mod.Health,
		RegistrationId: mod.RegistrationID,
		MenuCount:      mod.MenuCount,
		ApiCount:       mod.APICount,
		RouteCount:     mod.RouteCount,
	}

	if !mod.RegisteredAt.IsZero() {
		protoMod.RegisteredAt = timestamppb.New(mod.RegisteredAt)
	}
	if !mod.LastHeartbeat.IsZero() {
		protoMod.LastHeartbeat = timestamppb.New(mod.LastHeartbeat)
	}

	return protoMod
}

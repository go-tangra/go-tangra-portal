package service

import (
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
)

// MenuInjector handles storing menus from registered modules in-memory.
// Menus are NOT persisted to the database - they are served dynamically
// based on which modules are currently registered and healthy.
type MenuInjector struct {
	log      *log.Helper
	registry *ModuleRegistry
}

// NewMenuInjector creates a new MenuInjector.
func NewMenuInjector(ctx *bootstrap.Context, registry *ModuleRegistry) *MenuInjector {
	return &MenuInjector{
		log:      ctx.NewLoggerHelper("menu-injector/admin-service"),
		registry: registry,
	}
}

// InjectedMenu represents the result of storing a menu in-memory.
type InjectedMenu struct {
	SourceID string // Original ID from the OpenAPI spec
	ModuleID string // Module that owns this menu
}

// InjectMenus stores menus from a module's OpenAPI spec in-memory.
// Menus are stored in the ModuleRegistry and served dynamically.
// Returns the list of menus that were stored.
func (i *MenuInjector) InjectMenus(moduleID string, menus []*ParsedMenu) ([]*InjectedMenu, error) {
	if len(menus) == 0 {
		return nil, nil
	}

	// Store menus in the registry (in-memory)
	i.registry.SetModuleMenus(moduleID, menus)

	// Build result list
	injected := make([]*InjectedMenu, 0, len(menus))
	for _, m := range menus {
		injected = append(injected, &InjectedMenu{
			SourceID: m.ID,
			ModuleID: moduleID,
		})
	}

	i.log.Infof("Stored %d menus in-memory for module %s", len(injected), moduleID)
	return injected, nil
}

// RemoveModuleMenus removes all menus belonging to a module from memory.
// This is called when a module unregisters.
func (i *MenuInjector) RemoveModuleMenus(moduleID string) (int, error) {
	// Get current menu count before clearing
	mod, exists := i.registry.Get(moduleID)
	if !exists {
		return 0, nil
	}

	count := len(mod.Menus)

	// Clear menus from registry
	i.registry.SetModuleMenus(moduleID, nil)

	i.log.Infof("Removed %d menus from memory for module %s", count, moduleID)
	return count, nil
}

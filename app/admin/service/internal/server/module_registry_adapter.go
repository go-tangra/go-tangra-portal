package server

import (
	"github.com/go-tangra/go-tangra-common/gateway"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/service"
)

// ModuleRegistryAdapter wraps *service.ModuleRegistry to implement gateway.ModuleRegistry.
type ModuleRegistryAdapter struct {
	registry *service.ModuleRegistry
}

// NewModuleRegistryAdapter creates a new ModuleRegistryAdapter.
func NewModuleRegistryAdapter(registry *service.ModuleRegistry) *ModuleRegistryAdapter {
	return &ModuleRegistryAdapter{registry: registry}
}

// Get returns a module by its ID.
func (a *ModuleRegistryAdapter) Get(moduleID string) (*gateway.ModuleInfo, bool) {
	mod, ok := a.registry.Get(moduleID)
	if !ok {
		return nil, false
	}
	return toModuleInfo(mod), true
}

// List returns all registered modules.
func (a *ModuleRegistryAdapter) List() []*gateway.ModuleInfo {
	modules := a.registry.List()
	result := make([]*gateway.ModuleInfo, 0, len(modules))
	for _, mod := range modules {
		result = append(result, toModuleInfo(mod))
	}
	return result
}

// OnEvent registers a handler for module lifecycle events.
func (a *ModuleRegistryAdapter) OnEvent(handler gateway.ModuleEventHandler) {
	a.registry.OnEvent(func(event service.ModuleRegistryEvent) {
		handler(gateway.ModuleEvent{
			Type:   convertEventType(event.Type),
			Module: toModuleInfo(event.Module),
		})
	})
}

func toModuleInfo(mod *service.RegisteredModule) *gateway.ModuleInfo {
	return &gateway.ModuleInfo{
		ModuleID:        mod.ModuleID,
		GrpcEndpoint:    mod.GrpcEndpoint,
		ProtoDescriptor: mod.ProtoDescriptor,
		Health:          mod.Health.String(),
	}
}

func convertEventType(t service.ModuleEventType) gateway.ModuleEventType {
	switch t {
	case service.ModuleEventRegistered:
		return gateway.ModuleEventRegistered
	case service.ModuleEventUnregistered:
		return gateway.ModuleEventUnregistered
	case service.ModuleEventUpdated:
		return gateway.ModuleEventUpdated
	case service.ModuleEventHealthChanged:
		return gateway.ModuleEventHealthChanged
	default:
		// Unknown event types map to HealthChanged so the router logs but takes no action.
		return gateway.ModuleEventHealthChanged
	}
}

package server

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	authnEngine "github.com/tx7do/kratos-authn/engine"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/service"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/transcoder"
)

// DynamicRouter handles routing for dynamically registered modules
// It uses sync.Map for lock-free reads on the hot path
type DynamicRouter struct {
	log           *log.Helper
	transcoder    *transcoder.Transcoder
	registry      *service.ModuleRegistry
	authenticator authnEngine.Authenticator

	// Module handlers (module_id -> *ModuleHandler)
	handlers sync.Map
}

// NewDynamicRouter creates a new DynamicRouter
func NewDynamicRouter(
	ctx *bootstrap.Context,
	transcoder *transcoder.Transcoder,
	registry *service.ModuleRegistry,
	authenticator authnEngine.Authenticator,
) *DynamicRouter {
	dr := &DynamicRouter{
		log:           ctx.NewLoggerHelper("dynamic-router/admin-service"),
		transcoder:    transcoder,
		registry:      registry,
		authenticator: authenticator,
	}

	// Subscribe to module events for hot-reload
	registry.OnEvent(dr.handleModuleEvent)

	return dr
}

// handleModuleEvent handles module lifecycle events
func (dr *DynamicRouter) handleModuleEvent(event service.ModuleRegistryEvent) {
	switch event.Type {
	case service.ModuleEventRegistered, service.ModuleEventUpdated:
		dr.registerModuleHandler(event.Module)
	case service.ModuleEventUnregistered:
		dr.unregisterModuleHandler(event.Module.ModuleID)
	case service.ModuleEventHealthChanged:
		// Could disable routing to unhealthy modules
		dr.log.Infof("Module %s health changed to %s", event.Module.ModuleID, event.Module.Health)
	}
}

// registerModuleHandler creates and registers a handler for a module
func (dr *DynamicRouter) registerModuleHandler(module *service.RegisteredModule) {
	// Only register if proto descriptor is available
	if len(module.ProtoDescriptor) == 0 {
		dr.log.Warnf("Module %s has no proto descriptor, skipping dynamic routing", module.ModuleID)
		return
	}

	// Register with transcoder
	if err := dr.transcoder.RegisterModule(module.ModuleID, module.GrpcEndpoint, module.ProtoDescriptor); err != nil {
		dr.log.Errorf("Failed to register module %s with transcoder: %v", module.ModuleID, err)
		return
	}

	// Create handler
	handler := NewModuleHandler(module.ModuleID, dr.transcoder, dr.log)
	dr.handlers.Store(module.ModuleID, handler)

	dr.log.Infof("Hot-registered dynamic handler for module: %s at endpoint %s",
		module.ModuleID, module.GrpcEndpoint)
}

// unregisterModuleHandler removes a module handler
func (dr *DynamicRouter) unregisterModuleHandler(moduleID string) {
	dr.handlers.Delete(moduleID)

	if err := dr.transcoder.UnregisterModule(moduleID); err != nil {
		dr.log.Warnf("Failed to unregister module %s from transcoder: %v", moduleID, err)
	}

	dr.log.Infof("Hot-unregistered dynamic handler for module: %s", moduleID)
}

// LoadExistingModules loads handlers for already registered modules
// This should be called during startup after the registry has loaded from database
func (dr *DynamicRouter) LoadExistingModules() {
	modules := dr.registry.List()
	for _, module := range modules {
		dr.registerModuleHandler(module)
	}
	dr.log.Infof("Loaded %d existing module handlers", len(modules))
}

// ServeHTTP implements http.Handler for the dynamic router
// Route format: /admin/v1/modules/{module_id}/{rest_of_path}
func (dr *DynamicRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract module ID from path
	// Path should be like: /admin/v1/modules/echo/v1/messages
	path := r.URL.Path
	moduleID, modulePath := dr.extractModuleFromPath(path)

	if moduleID == "" {
		dr.writeError(w, http.StatusBadRequest, "missing module ID in path")
		return
	}

	// Authenticate: extract Bearer token and set auth claims in request context
	// The Kratos middleware chain does not cover HandlePrefix routes, so we must
	// authenticate here to ensure the transcoder can inject user metadata (x-user-id, etc.)
	r = dr.authenticateRequest(r)

	// Look up handler
	val, ok := dr.handlers.Load(moduleID)
	if !ok {
		dr.writeError(w, http.StatusNotFound, "module not found: %s", moduleID)
		return
	}

	handler := val.(*ModuleHandler)
	handler.ServeHTTP(w, r, modulePath)
}

// authenticateRequest parses the Bearer token from the Authorization header,
// validates it, and returns a new request with auth claims set in the context.
func (dr *DynamicRouter) authenticateRequest(r *http.Request) *http.Request {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) <= 7 || !strings.EqualFold(authHeader[:7], "bearer ") {
		dr.log.Warnf("No Bearer token in Authorization header (header length=%d)", len(authHeader))
		return r
	}

	token := authHeader[7:]
	dr.log.Debugf("Authenticating token (length=%d) for %s %s", len(token), r.Method, r.URL.Path)
	claims, err := dr.authenticator.AuthenticateToken(token)
	if err != nil {
		dr.log.Warnf("Failed to authenticate token for module request: %v", err)
		return r
	}

	dr.log.Debugf("Successfully authenticated token, setting claims in context")
	ctx := authnEngine.ContextWithAuthClaims(r.Context(), claims)
	return r.WithContext(ctx)
}

// extractModuleFromPath extracts the module ID and remaining path
// Input:  /admin/v1/modules/echo/v1/messages
// Output: "echo", "/v1/messages"
func (dr *DynamicRouter) extractModuleFromPath(path string) (moduleID, modulePath string) {
	// Remove the prefix: /admin/v1/modules/
	const prefix = "/admin/v1/modules/"
	if !strings.HasPrefix(path, prefix) {
		return "", ""
	}

	remaining := strings.TrimPrefix(path, prefix)
	if remaining == "" {
		return "", ""
	}

	// Find the first slash to separate module ID from the rest
	slashIdx := strings.Index(remaining, "/")
	if slashIdx == -1 {
		// Just the module ID, no path
		return remaining, "/"
	}

	moduleID = remaining[:slashIdx]
	modulePath = remaining[slashIdx:]
	return moduleID, modulePath
}

// writeError writes an error response
func (dr *DynamicRouter) writeError(w http.ResponseWriter, code int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"code":%d,"message":"%s"}`, code, msg)))
}

// ListRegisteredModules returns a list of all modules with registered handlers
func (dr *DynamicRouter) ListRegisteredModules() []string {
	var modules []string
	dr.handlers.Range(func(key, value interface{}) bool {
		modules = append(modules, key.(string))
		return true
	})
	return modules
}

// GetModuleRoutes returns all routes for a specific module
func (dr *DynamicRouter) GetModuleRoutes(moduleID string) ([]transcoder.RouteInfo, error) {
	methods, err := dr.transcoder.GetModuleMethods(moduleID)
	if err != nil {
		return nil, err
	}

	var routes []transcoder.RouteInfo
	for _, method := range methods {
		for _, rule := range method.HTTPRules {
			routes = append(routes, transcoder.RouteInfo{
				ModuleID:    moduleID,
				ServiceName: method.ServiceName,
				MethodName:  method.MethodName,
				HTTPMethod:  rule.Method,
				Pattern:     "/admin/v1/modules/" + moduleID + rule.Pattern,
				FullMethod:  method.FullName,
			})
		}
	}
	return routes, nil
}

// GetAllRoutes returns all routes across all registered modules
func (dr *DynamicRouter) GetAllRoutes() []transcoder.RouteInfo {
	return dr.transcoder.ListRoutes()
}

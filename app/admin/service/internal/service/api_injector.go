package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/go-utils/trans"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"

	permissionV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/permission/service/v1"
)

// APIInjector handles injecting API resources from registered modules into the database.
type APIInjector struct {
	log     *log.Helper
	apiRepo *data.ApiRepo
}

// NewAPIInjector creates a new APIInjector.
func NewAPIInjector(ctx *bootstrap.Context, apiRepo *data.ApiRepo) *APIInjector {
	return &APIInjector{
		log:     ctx.NewLoggerHelper("api-injector/admin-service"),
		apiRepo: apiRepo,
	}
}

// InjectedAPI represents the result of injecting an API.
type InjectedAPI struct {
	APIID      uint32 // Database ID of the injected API
	Path       string // HTTP path
	Method     string // HTTP method
	ModuleID   string // Module that owns this API
	WasCreated bool   // True if API was created, false if updated
}

// InjectAPIs injects APIs from a module's OpenAPI spec into the database.
// It returns the list of API IDs that were created/updated.
func (i *APIInjector) InjectAPIs(ctx context.Context, moduleID string, apis []*ParsedAPI) ([]*InjectedAPI, error) {
	if len(apis) == 0 {
		return nil, nil
	}

	injected := make([]*InjectedAPI, 0, len(apis))

	for _, parsedAPI := range apis {
		result, err := i.injectSingleAPI(ctx, moduleID, parsedAPI)
		if err != nil {
			i.log.Errorf("Failed to inject API %s %s: %v", parsedAPI.Method, parsedAPI.Path, err)
			continue
		}
		injected = append(injected, result)
	}

	i.log.Infof("Injected %d APIs for module %s", len(injected), moduleID)
	return injected, nil
}

// injectSingleAPI injects a single API into the database using upsert logic.
func (i *APIInjector) injectSingleAPI(ctx context.Context, moduleID string, parsed *ParsedAPI) (*InjectedAPI, error) {
	// Build the full path with module prefix
	// Format: /admin/v1/modules/{module_id}{path}
	fullPath := fmt.Sprintf("/admin/v1/modules/%s%s", moduleID, parsed.Path)

	// Normalize method to uppercase (APIs are stored with uppercase methods)
	method := strings.ToUpper(parsed.Method)

	// Use upsert to handle both create and update cases atomically
	api, err := i.apiRepo.UpsertAPI(ctx, &permissionV1.Api{
		Path:        trans.Ptr(fullPath),
		Method:      trans.Ptr(method),
		Module:      trans.Ptr(moduleID),
		Operation:   trans.Ptr(parsed.OperationID),
		Description: trans.Ptr(parsed.Summary),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upsert API: %w", err)
	}

	return &InjectedAPI{
		APIID:    api.ID,
		Path:     fullPath,
		Method:   method,
		ModuleID: moduleID,
	}, nil
}

// RemoveModuleAPIs removes all APIs belonging to a module.
func (i *APIInjector) RemoveModuleAPIs(ctx context.Context, moduleID string) (int, error) {
	// Find all APIs with the module path prefix
	prefix := fmt.Sprintf("/admin/v1/modules/%s/", moduleID)
	apis, err := i.apiRepo.FindAPIsByPathPrefix(ctx, prefix)
	if err != nil {
		return 0, fmt.Errorf("failed to find module APIs: %w", err)
	}

	// Delete each API
	deleted := 0
	for _, api := range apis {
		if err := i.apiRepo.DeleteByID(ctx, api.ID); err != nil {
			i.log.Errorf("Failed to delete API %d: %v", api.ID, err)
			continue
		}
		deleted++
	}

	i.log.Infof("Removed %d APIs for module %s", deleted, moduleID)
	return deleted, nil
}

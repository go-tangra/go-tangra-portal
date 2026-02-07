package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/go-utils/trans"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"

	paginationV1 "github.com/tx7do/go-crud/api/gen/go/pagination/v1"
	permissionV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/permission/service/v1"
)

// PermissionGroupInjector handles injecting permission groups and their permissions
// from registered modules into the database.
type PermissionGroupInjector struct {
	log                 *log.Helper
	permissionGroupRepo *data.PermissionGroupRepo
	permissionRepo      *data.PermissionRepo
}

// NewPermissionGroupInjector creates a new PermissionGroupInjector.
func NewPermissionGroupInjector(
	ctx *bootstrap.Context,
	permissionGroupRepo *data.PermissionGroupRepo,
	permissionRepo *data.PermissionRepo,
) *PermissionGroupInjector {
	return &PermissionGroupInjector{
		log:                 ctx.NewLoggerHelper("permission-group-injector/admin-service"),
		permissionGroupRepo: permissionGroupRepo,
		permissionRepo:      permissionRepo,
	}
}

// InjectedPermissionGroup represents the result of injecting a permission group.
type InjectedPermissionGroup struct {
	GroupID          uint32
	Name             string
	ModuleID         string
	PermissionCount  int
	PermissionsCount int
}

// InjectPermissionGroups creates or updates permission groups and their permissions from a module.
// Permission groups are persisted to the database with the module field set for tracking.
func (i *PermissionGroupInjector) InjectPermissionGroups(ctx context.Context, moduleID string, groups []*ParsedPermissionGroup) ([]*InjectedPermissionGroup, error) {
	if len(groups) == 0 {
		return nil, nil
	}

	injected := make([]*InjectedPermissionGroup, 0, len(groups))

	for _, group := range groups {
		// Use the module from the group definition, or fall back to moduleID
		module := group.Module
		if module == "" {
			module = moduleID
		}

		// Check if the permission group already exists by name and module
		existingGroup, err := i.findGroupByNameAndModule(ctx, group.Name, module)
		if err != nil {
			i.log.Errorf("Failed to check existing permission group %s: %v", group.Name, err)
			continue
		}

		var groupID uint32
		if existingGroup != nil {
			// Update existing group
			groupID = existingGroup.GetId()
			err = i.permissionGroupRepo.Update(ctx, &permissionV1.UpdatePermissionGroupRequest{
				Id:           groupID,
				AllowMissing: trans.Ptr(false),
				Data: &permissionV1.PermissionGroup{
					Id:          &groupID,
					Name:        &group.Name,
					Module:      &module,
					Description: &group.Description,
					Status:      permissionV1.PermissionGroup_ON.Enum(),
				},
			})
			if err != nil {
				i.log.Errorf("Failed to update permission group %s: %v", group.Name, err)
				continue
			}
			i.log.Infof("Updated permission group: %s (id=%d)", group.Name, groupID)
		} else {
			// Create new group
			createdGroup, err := i.permissionGroupRepo.Create(ctx, &permissionV1.CreatePermissionGroupRequest{
				Data: &permissionV1.PermissionGroup{
					Name:        &group.Name,
					Module:      &module,
					Description: &group.Description,
					Status:      permissionV1.PermissionGroup_ON.Enum(),
				},
			})
			if err != nil {
				i.log.Errorf("Failed to create permission group %s: %v", group.Name, err)
				continue
			}
			groupID = createdGroup.GetId()
			i.log.Infof("Created permission group: %s (id=%d)", group.Name, groupID)
		}

		// Inject permissions for this group
		permCount := 0
		for _, perm := range group.Permissions {
			if err := i.injectPermission(ctx, groupID, perm); err != nil {
				i.log.Errorf("Failed to inject permission %s: %v", perm.Code, err)
				continue
			}
			permCount++
		}

		injected = append(injected, &InjectedPermissionGroup{
			GroupID:          groupID,
			Name:             group.Name,
			ModuleID:         module,
			PermissionCount:  len(group.Permissions),
			PermissionsCount: permCount,
		})
	}

	i.log.Infof("Injected %d permission groups for module %s", len(injected), moduleID)
	return injected, nil
}

// injectPermission creates or updates a single permission.
func (i *PermissionGroupInjector) injectPermission(ctx context.Context, groupID uint32, perm *ParsedPermission) error {
	// Check if permission already exists by code
	existingPerm, err := i.permissionRepo.Get(ctx, &permissionV1.GetPermissionRequest{
		QueryBy: &permissionV1.GetPermissionRequest_Code{Code: perm.Code},
	})

	if err == nil && existingPerm != nil {
		// Update existing permission
		return i.permissionRepo.Update(ctx, &permissionV1.UpdatePermissionRequest{
			Id:           existingPerm.GetId(),
			AllowMissing: trans.Ptr(false),
			Data: &permissionV1.Permission{
				Id:          existingPerm.Id,
				Name:        &perm.Name,
				Code:        &perm.Code,
				Description: &perm.Description,
				GroupId:     &groupID,
				Status:      permissionV1.Permission_ON.Enum(),
			},
		})
	}

	// Create new permission
	return i.permissionRepo.Create(ctx, &permissionV1.CreatePermissionRequest{
		Data: &permissionV1.Permission{
			Name:        &perm.Name,
			Code:        &perm.Code,
			Description: &perm.Description,
			GroupId:     &groupID,
			Status:      permissionV1.Permission_ON.Enum(),
		},
	})
}

// findGroupByNameAndModule finds a permission group by name and module.
func (i *PermissionGroupInjector) findGroupByNameAndModule(ctx context.Context, name, module string) (*permissionV1.PermissionGroup, error) {
	// List all groups and find matching one
	// This is not ideal but the repo doesn't have a direct lookup by name+module
	resp, err := i.permissionGroupRepo.List(ctx, &paginationV1.PagingRequest{
		NoPaging: trans.Ptr(true),
	}, false)
	if err != nil {
		return nil, err
	}

	for _, group := range resp.Items {
		if group.GetName() == name && group.GetModule() == module {
			return group, nil
		}
	}

	return nil, nil
}

// RemoveModulePermissionGroups removes all permission groups and their permissions for a module.
// This is called when a module unregisters.
func (i *PermissionGroupInjector) RemoveModulePermissionGroups(ctx context.Context, moduleID string) (int, error) {
	// Find all permission groups belonging to this module
	resp, err := i.permissionGroupRepo.List(ctx, &paginationV1.PagingRequest{
		NoPaging: trans.Ptr(true),
	}, false)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, group := range resp.Items {
		if group.GetModule() == moduleID {
			// Delete permissions in this group first
			if err := i.permissionRepo.Delete(ctx, &permissionV1.DeletePermissionRequest{
				DeleteBy: &permissionV1.DeletePermissionRequest_GroupId{GroupId: group.GetId()},
			}); err != nil {
				i.log.Warnf("Failed to delete permissions for group %s: %v", group.GetName(), err)
			}

			// Delete the group
			if err := i.permissionGroupRepo.Delete(ctx, &permissionV1.DeletePermissionGroupRequest{
				Id: group.GetId(),
			}); err != nil {
				i.log.Warnf("Failed to delete permission group %s: %v", group.GetName(), err)
				continue
			}

			count++
			i.log.Infof("Removed permission group: %s (id=%d)", group.GetName(), group.GetId())
		}
	}

	i.log.Infof("Removed %d permission groups for module %s", count, moduleID)
	return count, nil
}

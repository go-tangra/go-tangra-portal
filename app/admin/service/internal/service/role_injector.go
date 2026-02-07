package service

import (
	"context"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/go-utils/trans"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	paginationV1 "github.com/tx7do/go-crud/api/gen/go/pagination/v1"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/privacy"

	userV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/user/service/v1"
)

// RoleInjector handles injecting roles from registered modules into the database.
type RoleInjector struct {
	log            *log.Helper
	roleRepo       *data.RoleRepo
	permissionRepo *data.PermissionRepo
}

// NewRoleInjector creates a new RoleInjector.
func NewRoleInjector(
	ctx *bootstrap.Context,
	roleRepo *data.RoleRepo,
	permissionRepo *data.PermissionRepo,
) *RoleInjector {
	return &RoleInjector{
		log:            ctx.NewLoggerHelper("role-injector/admin-service"),
		roleRepo:       roleRepo,
		permissionRepo: permissionRepo,
	}
}

// InjectedRole represents the result of injecting a role.
type InjectedRole struct {
	RoleID          uint32
	Code            string
	Name            string
	PermissionCount int
}

// InjectRoles creates or updates roles from a module.
// Roles are persisted to the database with is_system=true for module roles.
func (i *RoleInjector) InjectRoles(ctx context.Context, moduleID string, roles []*ParsedRole) ([]*InjectedRole, error) {
	if len(roles) == 0 {
		return nil, nil
	}

	// Bypass privacy policy for system role injection
	ctx = privacy.DecisionContext(ctx, privacy.Allow)

	injected := make([]*InjectedRole, 0, len(roles))

	for _, role := range roles {
		// Check if the role already exists by code
		existingRole, err := i.roleRepo.Get(ctx, &userV1.GetRoleRequest{
			QueryBy: &userV1.GetRoleRequest_Code{Code: role.Code},
		})

		// Resolve permission codes to permission IDs
		permissionIDs, err := i.permissionRepo.GetPermissionIDsByCodes(ctx, role.Permissions)
		if err != nil {
			i.log.Warnf("Failed to resolve some permission codes for role %s: %v", role.Code, err)
			// Continue with whatever permissions we could resolve
		}

		var roleID uint32
		if existingRole != nil && existingRole.Id != nil {
			// Update existing role
			roleID = existingRole.GetId()
			err = i.roleRepo.Update(ctx, &userV1.UpdateRoleRequest{
				Id:           roleID,
				AllowMissing: trans.Ptr(false),
				Data: &userV1.Role{
					Id:          &roleID,
					Name:        &role.Name,
					Code:        &role.Code,
					Description: &role.Description,
					IsSystem:    trans.Ptr(role.IsSystem),
					IsProtected: trans.Ptr(true), // Module roles are protected
					Status:      userV1.Role_ON.Enum(),
					Permissions: permissionIDs,
				},
			})
			if err != nil {
				i.log.Errorf("Failed to update role %s: %v", role.Code, err)
				continue
			}
			i.log.Infof("Updated role: %s (id=%d)", role.Code, roleID)
		} else {
			// Create new role
			err = i.roleRepo.Create(ctx, &userV1.CreateRoleRequest{
				Data: &userV1.Role{
					Name:        &role.Name,
					Code:        &role.Code,
					Description: &role.Description,
					IsSystem:    trans.Ptr(role.IsSystem),
					IsProtected: trans.Ptr(true), // Module roles are protected
					Status:      userV1.Role_ON.Enum(),
					TenantId:    trans.Ptr(uint32(0)), // System roles have tenant_id=0
					Permissions: permissionIDs,
				},
			})
			if err != nil {
				i.log.Errorf("Failed to create role %s: %v", role.Code, err)
				continue
			}

			// Get the created role to get its ID
			createdRole, err := i.roleRepo.Get(ctx, &userV1.GetRoleRequest{
				QueryBy: &userV1.GetRoleRequest_Code{Code: role.Code},
			})
			if err != nil {
				i.log.Errorf("Failed to retrieve created role %s: %v", role.Code, err)
				continue
			}
			roleID = createdRole.GetId()
			i.log.Infof("Created role: %s (id=%d)", role.Code, roleID)
		}

		injected = append(injected, &InjectedRole{
			RoleID:          roleID,
			Code:            role.Code,
			Name:            role.Name,
			PermissionCount: len(permissionIDs),
		})
	}

	i.log.Infof("Injected %d roles for module %s", len(injected), moduleID)
	return injected, nil
}

// RemoveModuleRoles removes all roles belonging to a module.
// Module roles are identified by their code prefix (e.g., "lcm." for LCM module).
// Only roles with is_system=true are considered module roles.
// Note: Since module roles are protected, we first unset the protection before deleting.
func (i *RoleInjector) RemoveModuleRoles(ctx context.Context, moduleID string) (int, error) {
	// Build the code prefix for this module (e.g., "lcm." for module "lcm")
	codePrefix := moduleID + "."

	// Find all roles with the module prefix
	// We list all roles and filter by code prefix since there's no direct query method
	resp, err := i.roleRepo.List(ctx, &paginationV1.PagingRequest{
		NoPaging: trans.Ptr(true),
	})
	if err != nil {
		i.log.Warnf("Could not list roles for module cleanup: %v", err)
		return 0, nil
	}

	count := 0
	for _, role := range resp.Items {
		roleCode := role.GetCode()
		// Check if this role belongs to the module (has the module prefix)
		if strings.HasPrefix(roleCode, codePrefix) && role.GetIsSystem() {
			// First, unset the protection flags to allow deletion
			err := i.roleRepo.Update(ctx, &userV1.UpdateRoleRequest{
				Id:           role.GetId(),
				AllowMissing: trans.Ptr(false),
				Data: &userV1.Role{
					Id:          role.Id,
					IsSystem:    trans.Ptr(false),
					IsProtected: trans.Ptr(false),
				},
			})
			if err != nil {
				i.log.Warnf("Failed to unprotect role %s for deletion: %v", roleCode, err)
				continue
			}

			// Now delete the role
			err = i.roleRepo.Delete(ctx, &userV1.DeleteRoleRequest{
				Id: role.GetId(),
			})
			if err != nil {
				i.log.Warnf("Failed to delete role %s: %v", roleCode, err)
				continue
			}
			count++
			i.log.Infof("Removed role: %s (id=%d)", roleCode, role.GetId())
		}
	}

	i.log.Infof("Removed %d roles for module %s", count, moduleID)
	return count, nil
}

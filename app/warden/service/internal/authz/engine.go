package authz

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
)

// PermissionTuple represents a permission relationship in the system
type PermissionTuple struct {
	ID           uint32
	TenantID     uint32
	ResourceType ResourceType
	ResourceID   string
	Relation     Relation
	SubjectType  SubjectType
	SubjectID    string
	GrantedBy    *uint32
	ExpiresAt    *time.Time
	CreateTime   time.Time
}

// ResourceLookup provides methods to look up resource hierarchies
type ResourceLookup interface {
	// GetFolderParentID returns the parent folder ID for a folder
	GetFolderParentID(ctx context.Context, tenantID uint32, folderID string) (*string, error)
	// GetSecretFolderID returns the folder ID for a secret
	GetSecretFolderID(ctx context.Context, tenantID uint32, secretID string) (*string, error)
	// GetUserRoleIDs returns the role IDs for a user
	GetUserRoleIDs(ctx context.Context, tenantID uint32, userID string) ([]string, error)
}

// PermissionStore provides methods to store and retrieve permissions
type PermissionStore interface {
	// GetDirectPermissions returns permissions directly on a resource
	GetDirectPermissions(ctx context.Context, tenantID uint32, resourceType ResourceType, resourceID string) ([]PermissionTuple, error)
	// GetSubjectPermissions returns all permissions for a subject
	GetSubjectPermissions(ctx context.Context, tenantID uint32, subjectType SubjectType, subjectID string) ([]PermissionTuple, error)
	// HasPermission checks if a specific permission exists
	HasPermission(ctx context.Context, tenantID uint32, resourceType ResourceType, resourceID string, subjectType SubjectType, subjectID string) (*PermissionTuple, error)
	// CreatePermission creates a new permission
	CreatePermission(ctx context.Context, tuple PermissionTuple) (*PermissionTuple, error)
	// DeletePermission deletes a permission
	DeletePermission(ctx context.Context, tenantID uint32, resourceType ResourceType, resourceID string, relation *Relation, subjectType SubjectType, subjectID string) error
	// ListResourcesBySubject lists resources accessible by a subject
	ListResourcesBySubject(ctx context.Context, tenantID uint32, subjectType SubjectType, subjectID string, resourceType ResourceType) ([]string, error)
}

// Engine implements Zanzibar-like permission checking
type Engine struct {
	store  PermissionStore
	lookup ResourceLookup
	log    *log.Helper
}

// NewEngine creates a new authorization engine
func NewEngine(store PermissionStore, lookup ResourceLookup, logger log.Logger) *Engine {
	return &Engine{
		store:  store,
		lookup: lookup,
		log:    log.NewHelper(log.With(logger, "module", "authz/engine")),
	}
}

// CheckContext contains context for permission checks
type CheckContext struct {
	TenantID     uint32
	UserID       string
	ResourceType ResourceType
	ResourceID   string
	Permission   Permission
}

// CheckResult represents the result of a permission check
type CheckResult struct {
	Allowed  bool
	Relation *Relation
	Reason   string
}

// Check performs a permission check following Zanzibar algorithm:
// 1. Check direct permission on resource
// 2. If resource is Secret, check parent Folder permissions
// 3. If Folder has parent, recursively check parent permissions
// 4. Check user's roles for indirect permissions
// 5. Check tenant-level permissions
func (e *Engine) Check(ctx context.Context, check CheckContext) CheckResult {
	e.log.Debugf("Checking permission: user=%s, resource=%s:%s, permission=%s",
		check.UserID, check.ResourceType, check.ResourceID, check.Permission)

	// Step 1: Check direct user permission on resource
	if result := e.checkDirectPermission(ctx, check, SubjectTypeUser, check.UserID); result.Allowed {
		return result
	}

	// Step 2: Check user's role permissions on resource
	roleIDs, err := e.lookup.GetUserRoleIDs(ctx, check.TenantID, check.UserID)
	if err != nil {
		e.log.Warnf("Failed to get user roles: %v", err)
	} else {
		for _, roleID := range roleIDs {
			if result := e.checkDirectPermission(ctx, check, SubjectTypeRole, roleID); result.Allowed {
				return result
			}
		}
	}

	// Step 3: Check tenant-level permissions
	if result := e.checkDirectPermission(ctx, check, SubjectTypeTenant, "all"); result.Allowed {
		return result
	}

	// Step 4: Check parent folder permissions (hierarchy)
	if result := e.checkHierarchy(ctx, check, roleIDs); result.Allowed {
		return result
	}

	return CheckResult{
		Allowed: false,
		Reason:  "no permission found",
	}
}

// checkDirectPermission checks for a direct permission on a resource
func (e *Engine) checkDirectPermission(ctx context.Context, check CheckContext, subjectType SubjectType, subjectID string) CheckResult {
	tuple, err := e.store.HasPermission(ctx, check.TenantID, check.ResourceType, check.ResourceID, subjectType, subjectID)
	if err != nil {
		e.log.Debugf("Error checking permission: %v", err)
		return CheckResult{Allowed: false, Reason: "error checking permission"}
	}

	if tuple == nil {
		return CheckResult{Allowed: false, Reason: "no direct permission"}
	}

	// Check if permission has expired
	if tuple.ExpiresAt != nil && tuple.ExpiresAt.Before(time.Now()) {
		return CheckResult{Allowed: false, Reason: "permission expired"}
	}

	// Check if the relation grants the required permission
	if RelationGrantsPermission(tuple.Relation, check.Permission) {
		relation := tuple.Relation
		return CheckResult{
			Allowed:  true,
			Relation: &relation,
			Reason:   "direct permission",
		}
	}

	return CheckResult{Allowed: false, Reason: "relation does not grant permission"}
}

// checkHierarchy checks parent folder permissions
func (e *Engine) checkHierarchy(ctx context.Context, check CheckContext, roleIDs []string) CheckResult {
	var parentFolderID *string

	// If resource is a secret, get its folder
	if check.ResourceType == ResourceTypeSecret {
		folderID, err := e.lookup.GetSecretFolderID(ctx, check.TenantID, check.ResourceID)
		if err != nil {
			e.log.Warnf("Failed to get secret folder: %v", err)
			return CheckResult{Allowed: false, Reason: "error getting secret folder"}
		}
		parentFolderID = folderID
	} else if check.ResourceType == ResourceTypeFolder {
		// If resource is a folder, get its parent
		parentID, err := e.lookup.GetFolderParentID(ctx, check.TenantID, check.ResourceID)
		if err != nil {
			e.log.Warnf("Failed to get folder parent: %v", err)
			return CheckResult{Allowed: false, Reason: "error getting folder parent"}
		}
		parentFolderID = parentID
	}

	// Traverse up the folder hierarchy
	visited := make(map[string]bool)
	for parentFolderID != nil {
		folderID := *parentFolderID

		// Prevent infinite loops
		if visited[folderID] {
			break
		}
		visited[folderID] = true

		// Create a check for the parent folder
		folderCheck := CheckContext{
			TenantID:     check.TenantID,
			UserID:       check.UserID,
			ResourceType: ResourceTypeFolder,
			ResourceID:   folderID,
			Permission:   check.Permission,
		}

		// Check user permission on folder
		if result := e.checkDirectPermission(ctx, folderCheck, SubjectTypeUser, check.UserID); result.Allowed {
			result.Reason = "inherited from parent folder"
			return result
		}

		// Check role permissions on folder
		for _, roleID := range roleIDs {
			if result := e.checkDirectPermission(ctx, folderCheck, SubjectTypeRole, roleID); result.Allowed {
				result.Reason = "inherited from parent folder via role"
				return result
			}
		}

		// Check tenant permission on folder
		if result := e.checkDirectPermission(ctx, folderCheck, SubjectTypeTenant, "all"); result.Allowed {
			result.Reason = "inherited from parent folder via tenant"
			return result
		}

		// Move to the next parent
		nextParent, err := e.lookup.GetFolderParentID(ctx, check.TenantID, folderID)
		if err != nil {
			e.log.Warnf("Failed to get folder parent: %v", err)
			break
		}
		parentFolderID = nextParent
	}

	return CheckResult{Allowed: false, Reason: "no inherited permission"}
}

// Grant grants a permission to a subject
func (e *Engine) Grant(ctx context.Context, tuple PermissionTuple) (*PermissionTuple, error) {
	return e.store.CreatePermission(ctx, tuple)
}

// Revoke revokes a permission from a subject
func (e *Engine) Revoke(ctx context.Context, tenantID uint32, resourceType ResourceType, resourceID string, relation *Relation, subjectType SubjectType, subjectID string) error {
	return e.store.DeletePermission(ctx, tenantID, resourceType, resourceID, relation, subjectType, subjectID)
}

// ListPermissions lists all permissions on a resource
func (e *Engine) ListPermissions(ctx context.Context, tenantID uint32, resourceType ResourceType, resourceID string) ([]PermissionTuple, error) {
	return e.store.GetDirectPermissions(ctx, tenantID, resourceType, resourceID)
}

// ListAccessibleResources lists all resources of a type accessible by a user
func (e *Engine) ListAccessibleResources(ctx context.Context, tenantID uint32, userID string, resourceType ResourceType, permission Permission) ([]string, error) {
	accessibleIDs := make(map[string]bool)

	// Get user's direct permissions
	userResources, err := e.store.ListResourcesBySubject(ctx, tenantID, SubjectTypeUser, userID, resourceType)
	if err != nil {
		return nil, err
	}
	for _, id := range userResources {
		accessibleIDs[id] = true
	}

	// Get user's role permissions
	roleIDs, err := e.lookup.GetUserRoleIDs(ctx, tenantID, userID)
	if err != nil {
		e.log.Warnf("Failed to get user roles: %v", err)
	} else {
		for _, roleID := range roleIDs {
			roleResources, err := e.store.ListResourcesBySubject(ctx, tenantID, SubjectTypeRole, roleID, resourceType)
			if err != nil {
				continue
			}
			for _, id := range roleResources {
				accessibleIDs[id] = true
			}
		}
	}

	// Get tenant-level permissions
	tenantResources, err := e.store.ListResourcesBySubject(ctx, tenantID, SubjectTypeTenant, "all", resourceType)
	if err == nil {
		for _, id := range tenantResources {
			accessibleIDs[id] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(accessibleIDs))
	for id := range accessibleIDs {
		result = append(result, id)
	}

	return result, nil
}

// GetEffectivePermissions returns all permissions a user has on a resource
func (e *Engine) GetEffectivePermissions(ctx context.Context, check CheckContext) ([]Permission, Relation) {
	var highestRelation Relation
	permissions := make(map[Permission]bool)

	// Check each permission type
	for _, perm := range []Permission{PermissionRead, PermissionWrite, PermissionDelete, PermissionShare} {
		checkWithPerm := check
		checkWithPerm.Permission = perm
		result := e.Check(ctx, checkWithPerm)
		if result.Allowed {
			permissions[perm] = true
			if result.Relation != nil && IsRelationAtLeast(*result.Relation, highestRelation) {
				highestRelation = *result.Relation
			}
		}
	}

	// Convert map to slice
	result := make([]Permission, 0, len(permissions))
	for perm := range permissions {
		result = append(result, perm)
	}

	return result, highestRelation
}

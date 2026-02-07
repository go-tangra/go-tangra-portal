package authz

import (
	"context"
	"fmt"
)

// Checker provides a simplified interface for permission checks
type Checker struct {
	engine *Engine
}

// NewChecker creates a new permission checker
func NewChecker(engine *Engine) *Checker {
	return &Checker{engine: engine}
}

// CanRead checks if a user can read a resource
func (c *Checker) CanRead(ctx context.Context, tenantID uint32, userID string, resourceType ResourceType, resourceID string) error {
	result := c.engine.Check(ctx, CheckContext{
		TenantID:     tenantID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Permission:   PermissionRead,
	})
	if !result.Allowed {
		return fmt.Errorf("access denied: %s", result.Reason)
	}
	return nil
}

// CanWrite checks if a user can write to a resource
func (c *Checker) CanWrite(ctx context.Context, tenantID uint32, userID string, resourceType ResourceType, resourceID string) error {
	result := c.engine.Check(ctx, CheckContext{
		TenantID:     tenantID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Permission:   PermissionWrite,
	})
	if !result.Allowed {
		return fmt.Errorf("access denied: %s", result.Reason)
	}
	return nil
}

// CanDelete checks if a user can delete a resource
func (c *Checker) CanDelete(ctx context.Context, tenantID uint32, userID string, resourceType ResourceType, resourceID string) error {
	result := c.engine.Check(ctx, CheckContext{
		TenantID:     tenantID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Permission:   PermissionDelete,
	})
	if !result.Allowed {
		return fmt.Errorf("access denied: %s", result.Reason)
	}
	return nil
}

// CanShare checks if a user can share a resource
func (c *Checker) CanShare(ctx context.Context, tenantID uint32, userID string, resourceType ResourceType, resourceID string) error {
	result := c.engine.Check(ctx, CheckContext{
		TenantID:     tenantID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Permission:   PermissionShare,
	})
	if !result.Allowed {
		return fmt.Errorf("access denied: %s", result.Reason)
	}
	return nil
}

// CheckPermission checks if a user has a specific permission on a resource
func (c *Checker) CheckPermission(ctx context.Context, tenantID uint32, userID string, resourceType ResourceType, resourceID string, permission Permission) (bool, string) {
	result := c.engine.Check(ctx, CheckContext{
		TenantID:     tenantID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Permission:   permission,
	})
	return result.Allowed, result.Reason
}

// RequirePermission checks if a user has a specific permission and returns an error if not
func (c *Checker) RequirePermission(ctx context.Context, tenantID uint32, userID string, resourceType ResourceType, resourceID string, permission Permission) error {
	allowed, reason := c.CheckPermission(ctx, tenantID, userID, resourceType, resourceID, permission)
	if !allowed {
		return fmt.Errorf("access denied: %s", reason)
	}
	return nil
}

// CanReadFolder is a convenience method for folder read checks
func (c *Checker) CanReadFolder(ctx context.Context, tenantID uint32, userID string, folderID string) error {
	return c.CanRead(ctx, tenantID, userID, ResourceTypeFolder, folderID)
}

// CanWriteFolder is a convenience method for folder write checks
func (c *Checker) CanWriteFolder(ctx context.Context, tenantID uint32, userID string, folderID string) error {
	return c.CanWrite(ctx, tenantID, userID, ResourceTypeFolder, folderID)
}

// CanDeleteFolder is a convenience method for folder delete checks
func (c *Checker) CanDeleteFolder(ctx context.Context, tenantID uint32, userID string, folderID string) error {
	return c.CanDelete(ctx, tenantID, userID, ResourceTypeFolder, folderID)
}

// CanShareFolder is a convenience method for folder share checks
func (c *Checker) CanShareFolder(ctx context.Context, tenantID uint32, userID string, folderID string) error {
	return c.CanShare(ctx, tenantID, userID, ResourceTypeFolder, folderID)
}

// CanReadSecret is a convenience method for secret read checks
func (c *Checker) CanReadSecret(ctx context.Context, tenantID uint32, userID string, secretID string) error {
	return c.CanRead(ctx, tenantID, userID, ResourceTypeSecret, secretID)
}

// CanWriteSecret is a convenience method for secret write checks
func (c *Checker) CanWriteSecret(ctx context.Context, tenantID uint32, userID string, secretID string) error {
	return c.CanWrite(ctx, tenantID, userID, ResourceTypeSecret, secretID)
}

// CanDeleteSecret is a convenience method for secret delete checks
func (c *Checker) CanDeleteSecret(ctx context.Context, tenantID uint32, userID string, secretID string) error {
	return c.CanDelete(ctx, tenantID, userID, ResourceTypeSecret, secretID)
}

// CanShareSecret is a convenience method for secret share checks
func (c *Checker) CanShareSecret(ctx context.Context, tenantID uint32, userID string, secretID string) error {
	return c.CanShare(ctx, tenantID, userID, ResourceTypeSecret, secretID)
}

// GetEffectivePermissions returns all effective permissions for a user on a resource
func (c *Checker) GetEffectivePermissions(ctx context.Context, tenantID uint32, userID string, resourceType ResourceType, resourceID string) ([]Permission, Relation) {
	return c.engine.GetEffectivePermissions(ctx, CheckContext{
		TenantID:     tenantID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	})
}

// ListAccessibleFolders lists all folders accessible by a user
func (c *Checker) ListAccessibleFolders(ctx context.Context, tenantID uint32, userID string) ([]string, error) {
	return c.engine.ListAccessibleResources(ctx, tenantID, userID, ResourceTypeFolder, PermissionRead)
}

// ListAccessibleSecrets lists all secrets accessible by a user
func (c *Checker) ListAccessibleSecrets(ctx context.Context, tenantID uint32, userID string) ([]string, error) {
	return c.engine.ListAccessibleResources(ctx, tenantID, userID, ResourceTypeSecret, PermissionRead)
}

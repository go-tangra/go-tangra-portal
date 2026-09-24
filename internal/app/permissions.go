package app

import (
	"context"
	"time"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
)

// registerPermissions declares a module's API permissions in the auth module
// for every tenant it serves (auth.v1.Authorization/RegisterPermissions).
func (a *App) registerPermissions(ctx context.Context, client authv1.AuthorizationClient, m manifest.Manifest) error {
	if len(m.Permissions) == 0 {
		return nil
	}
	req := &authv1.RegisterPermissionsRequest{}
	for _, p := range m.Permissions {
		req.Permissions = append(req.Permissions, &authv1.PermissionDef{Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := client.RegisterPermissions(ctx, req)
	return err
}

// SyncPermissions re-registers every module's permissions (new tenants pick
// them up; also run periodically from Run).
func (a *App) SyncPermissions(ctx context.Context) error {
	var first error
	for _, reg := range a.Reg.Registrations() {
		if err := a.registerPermissions(ctx, a.authz, reg.Manifest); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (a *App) permissionSyncLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.SyncPermissions(ctx); err != nil {
				a.Log.Warn("permission sync", "err", err)
			}
		}
	}
}

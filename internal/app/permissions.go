package app

import (
	"context"
	"time"

	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
)

// registerPermissions declares a module's API permissions in the auth module
// for every tenant it serves (auth.v1.Authorization/RegisterPermissions). The
// gateway registers on the module's behalf: the request names the module and
// its display name and carries permissions only — roles, role sets and
// built-in grants are the module's own registration (auth refuses them from
// the gateway).
func (a *App) registerPermissions(ctx context.Context, client authv1.AuthorizationClient, m manifest.Manifest) error {
	if len(m.Permissions) == 0 {
		return nil
	}
	req := &authv1.RegisterPermissionsRequest{Module: m.Module, ModuleDisplayName: m.DisplayName}
	for _, p := range m.Permissions {
		req.Permissions = append(req.Permissions, &authv1.PermissionDef{Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := client.RegisterPermissions(ctx, req)
	return err
}

// SyncPermissions re-registers every module's permissions (new tenants pick
// them up; also run periodically from Run). A refused registration (for
// example InvalidArgument) is logged and the other modules still register;
// the first error is returned.
func (a *App) SyncPermissions(ctx context.Context) error {
	var first error
	for _, reg := range a.Reg.Registrations() {
		if err := a.registerPermissions(ctx, a.authz, reg.Manifest); err != nil {
			a.Log.Warn("permission registration with auth failed", "module", reg.Module, "code", status.Code(err).String(), "err", err)
			if first == nil {
				first = err
			}
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

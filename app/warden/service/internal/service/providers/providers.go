package providers

import (
	"context"

	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/authz"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data"
)

// ProvideResourceLookup creates a ResourceLookup from repositories
func ProvideResourceLookup(folderRepo *data.FolderRepo, secretRepo *data.SecretRepo) authz.ResourceLookup {
	return &resourceLookupImpl{
		folderRepo: folderRepo,
		secretRepo: secretRepo,
	}
}

// ProvidePermissionStore creates a PermissionStore from the permission repo
func ProvidePermissionStore(permRepo *data.PermissionRepo) authz.PermissionStore {
	return permRepo
}

// ProvideAuthzEngine creates the authorization engine
func ProvideAuthzEngine(store authz.PermissionStore, lookup authz.ResourceLookup, ctx *bootstrap.Context) *authz.Engine {
	return authz.NewEngine(store, lookup, ctx.GetLogger())
}

// ProvideAuthzChecker creates the authorization checker
func ProvideAuthzChecker(engine *authz.Engine) *authz.Checker {
	return authz.NewChecker(engine)
}

// resourceLookupImpl implements authz.ResourceLookup
type resourceLookupImpl struct {
	folderRepo *data.FolderRepo
	secretRepo *data.SecretRepo
}

func (r *resourceLookupImpl) GetFolderParentID(ctx context.Context, tenantID uint32, folderID string) (*string, error) {
	return r.folderRepo.GetFolderParentID(ctx, tenantID, folderID)
}

func (r *resourceLookupImpl) GetSecretFolderID(ctx context.Context, tenantID uint32, secretID string) (*string, error) {
	return r.secretRepo.GetSecretFolderID(ctx, tenantID, secretID)
}

func (r *resourceLookupImpl) GetUserRoleIDs(ctx context.Context, tenantID uint32, userID string) ([]string, error) {
	// TODO: Implement proper role lookup from user service
	return nil, nil
}

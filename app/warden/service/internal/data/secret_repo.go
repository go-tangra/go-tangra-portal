package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent/folder"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent/secret"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
)

type SecretRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewSecretRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *SecretRepo {
	return &SecretRepo{
		log:       ctx.NewLoggerHelper("secret/repo"),
		entClient: entClient,
	}
}

// Create creates a new secret
func (r *SecretRepo) Create(ctx context.Context, tenantID uint32, folderID *string, name, username, hostURL, vaultPath, description string, metadata map[string]any, createdBy *uint32) (*ent.Secret, error) {
	id := uuid.New().String()

	builder := r.entClient.Client().Secret.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetVaultPath(vaultPath).
		SetCurrentVersion(1).
		SetStatus(secret.StatusSECRET_STATUS_ACTIVE).
		SetCreateTime(time.Now())

	if folderID != nil && *folderID != "" {
		builder.SetFolderID(*folderID)
	}
	if username != "" {
		builder.SetUsername(username)
	}
	if hostURL != "" {
		builder.SetHostURL(hostURL)
	}
	if description != "" {
		builder.SetDescription(description)
	}
	if metadata != nil {
		builder.SetMetadata(metadata)
	}
	if createdBy != nil {
		builder.SetCreateBy(*createdBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, wardenV1.ErrorSecretAlreadyExists("secret already exists")
		}
		r.log.Errorf("create secret failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("create secret failed")
	}

	return entity, nil
}

// GetByID retrieves a secret by ID
func (r *SecretRepo) GetByID(ctx context.Context, id string) (*ent.Secret, error) {
	entity, err := r.entClient.Client().Secret.Query().
		Where(secret.IDEQ(id)).
		WithFolder().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get secret failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get secret failed")
	}
	return entity, nil
}

// GetByTenantAndName retrieves a secret by tenant ID, folder ID, and name
func (r *SecretRepo) GetByTenantAndName(ctx context.Context, tenantID uint32, folderID *string, name string) (*ent.Secret, error) {
	query := r.entClient.Client().Secret.Query().
		Where(
			secret.TenantIDEQ(tenantID),
			secret.NameEQ(name),
		)

	if folderID != nil && *folderID != "" {
		query = query.Where(secret.FolderIDEQ(*folderID))
	} else {
		query = query.Where(secret.FolderIDIsNil())
	}

	entity, err := query.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get secret by name failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get secret failed")
	}
	return entity, nil
}

// List lists secrets with optional filters
func (r *SecretRepo) List(ctx context.Context, tenantID uint32, folderID *string, status *secret.Status, nameFilter *string, page, pageSize uint32) ([]*ent.Secret, int, error) {
	query := r.entClient.Client().Secret.Query().
		Where(secret.TenantIDEQ(tenantID))

	if folderID != nil {
		if *folderID == "" {
			// Root-level secrets
			query = query.Where(secret.FolderIDIsNil())
		} else {
			query = query.Where(secret.FolderIDEQ(*folderID))
		}
	}

	if status != nil {
		query = query.Where(secret.StatusEQ(*status))
	}

	if nameFilter != nil && *nameFilter != "" {
		query = query.Where(secret.NameContains(*nameFilter))
	}

	// Count total
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count secrets failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("count secrets failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		query = query.Offset(offset).Limit(int(pageSize))
	}

	entities, err := query.
		WithFolder().
		Order(ent.Asc(secret.FieldName)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list secrets failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("list secrets failed")
	}

	return entities, total, nil
}

// Update updates a secret's metadata
func (r *SecretRepo) Update(ctx context.Context, id string, name, username, hostURL, description *string, metadata map[string]any, status *secret.Status, updatedBy *uint32) (*ent.Secret, error) {
	builder := r.entClient.Client().Secret.UpdateOneID(id).
		SetUpdateTime(time.Now())

	if name != nil {
		builder.SetName(*name)
	}
	if username != nil {
		builder.SetUsername(*username)
	}
	if hostURL != nil {
		builder.SetHostURL(*hostURL)
	}
	if description != nil {
		builder.SetDescription(*description)
	}
	if metadata != nil {
		builder.SetMetadata(metadata)
	}
	if status != nil {
		builder.SetStatus(*status)
	}
	if updatedBy != nil {
		builder.SetUpdateBy(*updatedBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, wardenV1.ErrorSecretNotFound("secret not found")
		}
		if ent.IsConstraintError(err) {
			return nil, wardenV1.ErrorSecretAlreadyExists("secret with this name already exists")
		}
		r.log.Errorf("update secret failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("update secret failed")
	}

	return entity, nil
}

// UpdateVersion updates the current version of a secret
func (r *SecretRepo) UpdateVersion(ctx context.Context, id string, version int32, updatedBy *uint32) (*ent.Secret, error) {
	builder := r.entClient.Client().Secret.UpdateOneID(id).
		SetCurrentVersion(version).
		SetUpdateTime(time.Now())

	if updatedBy != nil {
		builder.SetUpdateBy(*updatedBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, wardenV1.ErrorSecretNotFound("secret not found")
		}
		r.log.Errorf("update secret version failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("update secret version failed")
	}

	return entity, nil
}

// Move moves a secret to a different folder
func (r *SecretRepo) Move(ctx context.Context, id string, newFolderID *string, updatedBy *uint32) (*ent.Secret, error) {
	builder := r.entClient.Client().Secret.UpdateOneID(id).
		SetUpdateTime(time.Now())

	if newFolderID != nil && *newFolderID != "" {
		builder.SetFolderID(*newFolderID)
	} else {
		builder.ClearFolderID()
	}

	if updatedBy != nil {
		builder.SetUpdateBy(*updatedBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, wardenV1.ErrorSecretNotFound("secret not found")
		}
		if ent.IsConstraintError(err) {
			return nil, wardenV1.ErrorSecretAlreadyExists("secret with this name already exists in the destination folder")
		}
		r.log.Errorf("move secret failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("move secret failed")
	}

	return entity, nil
}

// Delete deletes a secret (soft or permanent)
func (r *SecretRepo) Delete(ctx context.Context, id string, permanent bool) error {
	if permanent {
		err := r.entClient.Client().Secret.DeleteOneID(id).Exec(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return wardenV1.ErrorSecretNotFound("secret not found")
			}
			r.log.Errorf("delete secret failed: %s", err.Error())
			return wardenV1.ErrorInternalServerError("delete secret failed")
		}
	} else {
		_, err := r.entClient.Client().Secret.UpdateOneID(id).
			SetStatus(secret.StatusSECRET_STATUS_DELETED).
			SetUpdateTime(time.Now()).
			Save(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return wardenV1.ErrorSecretNotFound("secret not found")
			}
			r.log.Errorf("soft delete secret failed: %s", err.Error())
			return wardenV1.ErrorInternalServerError("delete secret failed")
		}
	}
	return nil
}

// Search searches secrets by query
func (r *SecretRepo) Search(ctx context.Context, tenantID uint32, query string, folderID *string, includeSubfolders bool, status *secret.Status, page, pageSize uint32) ([]*ent.Secret, int, error) {
	q := r.entClient.Client().Secret.Query().
		Where(secret.TenantIDEQ(tenantID))

	// Add search predicates
	searchPredicate := secret.Or(
		secret.NameContains(query),
		secret.UsernameContains(query),
		secret.HostURLContains(query),
		secret.DescriptionContains(query),
	)
	q = q.Where(searchPredicate)

	if folderID != nil && *folderID != "" {
		if includeSubfolders {
			// This would need path-based search if folders have paths
			// For now, just search in the specified folder
			q = q.Where(secret.FolderIDEQ(*folderID))
		} else {
			q = q.Where(secret.FolderIDEQ(*folderID))
		}
	}

	if status != nil {
		q = q.Where(secret.StatusEQ(*status))
	}

	// Count total
	total, err := q.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count search results failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("search secrets failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		q = q.Offset(offset).Limit(int(pageSize))
	}

	entities, err := q.
		WithFolder().
		Order(ent.Asc(secret.FieldName)).
		All(ctx)
	if err != nil {
		r.log.Errorf("search secrets failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("search secrets failed")
	}

	return entities, total, nil
}

// GetSecretFolderID returns the folder ID for a secret (implements ResourceLookup interface)
func (r *SecretRepo) GetSecretFolderID(ctx context.Context, tenantID uint32, secretID string) (*string, error) {
	s, err := r.GetByID(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, nil
	}
	return s.FolderID, nil
}

// ListAll returns all secrets for a tenant (for export operations)
func (r *SecretRepo) ListAll(ctx context.Context, tenantID uint32) ([]*ent.Secret, error) {
	entities, err := r.entClient.Client().Secret.Query().
		Where(secret.TenantIDEQ(tenantID)).
		Where(secret.StatusNEQ(secret.StatusSECRET_STATUS_DELETED)).
		WithFolder().
		Order(ent.Asc(secret.FieldName)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list all secrets failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("list all secrets failed")
	}
	return entities, nil
}

// ListAllInFolderTree returns all secrets in a folder and its subfolders
func (r *SecretRepo) ListAllInFolderTree(ctx context.Context, tenantID uint32, folderID string) ([]*ent.Secret, error) {
	// Get the folder to get its path
	f, err := r.entClient.Client().Folder.Get(ctx, folderID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get folder failed")
	}

	// Get all folder IDs in the tree
	folderIDs := []string{folderID}

	// Get subfolders recursively using path prefix
	folders, err := r.entClient.Client().Folder.Query().
		Where(folder.PathHasPrefix(f.Path + "/")).
		All(ctx)

	if err == nil {
		for _, sf := range folders {
			folderIDs = append(folderIDs, sf.ID)
		}
	}

	entities, err := r.entClient.Client().Secret.Query().
		Where(secret.TenantIDEQ(tenantID)).
		Where(secret.StatusNEQ(secret.StatusSECRET_STATUS_DELETED)).
		Where(secret.FolderIDIn(folderIDs...)).
		WithFolder().
		Order(ent.Asc(secret.FieldName)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list secrets in folder tree failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("list secrets in folder tree failed")
	}
	return entities, nil
}

// ToProto converts an ent.Secret to wardenV1.Secret
func (r *SecretRepo) ToProto(entity *ent.Secret) *wardenV1.Secret {
	if entity == nil {
		return nil
	}

	proto := &wardenV1.Secret{
		Id:             entity.ID,
		TenantId:       derefUint32(entity.TenantID),
		Name:           entity.Name,
		Username:       entity.Username,
		HostUrl:        entity.HostURL,
		Description:    entity.Description,
		CurrentVersion: entity.CurrentVersion,
	}

	if entity.FolderID != nil {
		proto.FolderId = entity.FolderID
	}

	// Get folder path if folder is loaded
	if entity.Edges.Folder != nil {
		proto.FolderPath = entity.Edges.Folder.Path
	}

	// Map status
	switch entity.Status {
	case secret.StatusSECRET_STATUS_ACTIVE:
		proto.Status = wardenV1.SecretStatus_SECRET_STATUS_ACTIVE
	case secret.StatusSECRET_STATUS_ARCHIVED:
		proto.Status = wardenV1.SecretStatus_SECRET_STATUS_ARCHIVED
	case secret.StatusSECRET_STATUS_DELETED:
		proto.Status = wardenV1.SecretStatus_SECRET_STATUS_DELETED
	default:
		proto.Status = wardenV1.SecretStatus_SECRET_STATUS_UNSPECIFIED
	}

	// Convert metadata
	if entity.Metadata != nil {
		metadataStruct, err := structpb.NewStruct(entity.Metadata)
		if err == nil {
			proto.Metadata = metadataStruct
		}
	}

	// Convert timestamps
	if entity.CreateBy != nil {
		proto.CreatedBy = entity.CreateBy
	}
	if entity.UpdateBy != nil {
		proto.UpdatedBy = entity.UpdateBy
	}
	if entity.CreateTime != nil && !entity.CreateTime.IsZero() {
		proto.CreateTime = timestamppb.New(*entity.CreateTime)
	}
	if entity.UpdateTime != nil && !entity.UpdateTime.IsZero() {
		proto.UpdateTime = timestamppb.New(*entity.UpdateTime)
	}

	return proto
}

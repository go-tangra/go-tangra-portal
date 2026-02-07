package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/authz"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent/secret"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/pkg/vault"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
)

type SecretService struct {
	wardenV1.UnimplementedWardenSecretServiceServer

	log         *log.Helper
	secretRepo  *data.SecretRepo
	versionRepo *data.SecretVersionRepo
	folderRepo  *data.FolderRepo
	permRepo    *data.PermissionRepo
	kvStore     *vault.KVStore
	checker     *authz.Checker
}

func NewSecretService(
	ctx *bootstrap.Context,
	secretRepo *data.SecretRepo,
	versionRepo *data.SecretVersionRepo,
	folderRepo *data.FolderRepo,
	permRepo *data.PermissionRepo,
	kvStore *vault.KVStore,
	checker *authz.Checker,
) *SecretService {
	return &SecretService{
		log:         ctx.NewLoggerHelper("warden/service/secret"),
		secretRepo:  secretRepo,
		versionRepo: versionRepo,
		folderRepo:  folderRepo,
		permRepo:    permRepo,
		kvStore:     kvStore,
		checker:     checker,
	}
}

// CreateSecret creates a new secret
func (s *SecretService) CreateSecret(ctx context.Context, req *wardenV1.CreateSecretRequest) (*wardenV1.CreateSecretResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission on folder (if specified)
	if req.FolderId != nil && *req.FolderId != "" {
		if err := s.checker.CanWriteFolder(ctx, tenantID, userID, *req.FolderId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to create secret in this folder")
		}
	}

	// Build vault path
	secretID := generateUUID()
	vaultPath := s.kvStore.BuildPath(tenantID, secretID)

	// Store password in Vault
	_, err := s.kvStore.StorePassword(ctx, vaultPath, req.Password, nil)
	if err != nil {
		s.log.Errorf("failed to store password in Vault: %v", err)
		return nil, wardenV1.ErrorVaultOperationError("failed to store password")
	}

	// Convert metadata from proto struct to map
	var metadata map[string]any
	if req.Metadata != nil {
		metadata = req.Metadata.AsMap()
	}

	// Create secret in database
	createdBy := getUserIDAsUint32(ctx)
	secretEntity, err := s.secretRepo.Create(ctx, tenantID, req.FolderId, req.Name, req.Username, req.HostUrl, vaultPath, req.Description, metadata, createdBy)
	if err != nil {
		// Try to clean up Vault on failure
		_ = s.kvStore.DestroyAllVersions(ctx, vaultPath)
		return nil, err
	}

	// Create initial version record
	checksum := vault.CalculateChecksum(req.Password)
	_, err = s.versionRepo.Create(ctx, secretEntity.ID, 1, vaultPath, req.VersionComment, checksum, createdBy)
	if err != nil {
		s.log.Warnf("failed to create version record: %v", err)
	}

	// Grant owner permission to creator
	if createdBy != nil {
		_, err = s.permRepo.Create(ctx, tenantID, string(authz.ResourceTypeSecret), secretEntity.ID, string(authz.RelationOwner), string(authz.SubjectTypeUser), userID, createdBy, nil)
		if err != nil {
			s.log.Warnf("failed to grant owner permission: %v", err)
		}
	}

	return &wardenV1.CreateSecretResponse{
		Secret: s.secretRepo.ToProto(secretEntity),
	}, nil
}

// GetSecret gets a secret by ID (metadata only)
func (s *SecretService) GetSecret(ctx context.Context, req *wardenV1.GetSecretRequest) (*wardenV1.GetSecretResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanReadSecret(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to access this secret")
	}

	secretEntity, err := s.secretRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if secretEntity == nil {
		return nil, wardenV1.ErrorSecretNotFound("secret not found")
	}

	return &wardenV1.GetSecretResponse{
		Secret: s.secretRepo.ToProto(secretEntity),
	}, nil
}

// GetSecretPassword retrieves the password for a secret
func (s *SecretService) GetSecretPassword(ctx context.Context, req *wardenV1.GetSecretPasswordRequest) (*wardenV1.GetSecretPasswordResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanReadSecret(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to access this secret")
	}

	secretEntity, err := s.secretRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if secretEntity == nil {
		return nil, wardenV1.ErrorSecretNotFound("secret not found")
	}

	var password string
	var version int

	if req.Version != nil && *req.Version > 0 {
		// Get specific version
		versionEntity, err := s.versionRepo.GetBySecretAndVersion(ctx, req.Id, *req.Version)
		if err != nil {
			return nil, err
		}
		if versionEntity == nil {
			return nil, wardenV1.ErrorVersionNotFound("version not found")
		}
		password, err = s.kvStore.GetPasswordVersion(ctx, secretEntity.VaultPath, int(*req.Version))
		if err != nil {
			return nil, wardenV1.ErrorVaultOperationError("failed to retrieve password")
		}
		version = int(*req.Version)
	} else {
		// Get current version
		password, version, err = s.kvStore.GetPassword(ctx, secretEntity.VaultPath)
		if err != nil {
			return nil, wardenV1.ErrorVaultOperationError("failed to retrieve password")
		}
	}

	return &wardenV1.GetSecretPasswordResponse{
		Password: password,
		Version:  int32(version),
	}, nil
}

// ListSecrets lists secrets in a folder
func (s *SecretService) ListSecrets(ctx context.Context, req *wardenV1.ListSecretsRequest) (*wardenV1.ListSecretsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// If folder is specified, check permission
	if req.FolderId != nil && *req.FolderId != "" {
		if err := s.checker.CanReadFolder(ctx, tenantID, userID, *req.FolderId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to access this folder")
		}
	}

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	var status *secret.Status
	if req.Status != nil && *req.Status != wardenV1.SecretStatus_SECRET_STATUS_UNSPECIFIED {
		s := mapProtoStatusToEnt(*req.Status)
		status = &s
	}

	secrets, total, err := s.secretRepo.List(ctx, tenantID, req.FolderId, status, req.NameFilter, page, pageSize)
	if err != nil {
		return nil, err
	}

	// Filter secrets by permission
	accessibleSecrets := make([]*wardenV1.Secret, 0, len(secrets))
	for _, sec := range secrets {
		if err := s.checker.CanReadSecret(ctx, tenantID, userID, sec.ID); err == nil {
			accessibleSecrets = append(accessibleSecrets, s.secretRepo.ToProto(sec))
		}
	}

	return &wardenV1.ListSecretsResponse{
		Secrets: accessibleSecrets,
		Total:   uint32(total),
	}, nil
}

// UpdateSecret updates secret metadata
func (s *SecretService) UpdateSecret(ctx context.Context, req *wardenV1.UpdateSecretRequest) (*wardenV1.UpdateSecretResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanWriteSecret(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to modify this secret")
	}

	var metadata map[string]any
	if req.Metadata != nil {
		metadata = req.Metadata.AsMap()
	}

	var status *secret.Status
	if req.Status != nil && *req.Status != wardenV1.SecretStatus_SECRET_STATUS_UNSPECIFIED {
		s := mapProtoStatusToEnt(*req.Status)
		status = &s
	}

	updatedBy := getUserIDAsUint32(ctx)
	secretEntity, err := s.secretRepo.Update(ctx, req.Id, req.Name, req.Username, req.HostUrl, req.Description, metadata, status, updatedBy)
	if err != nil {
		return nil, err
	}

	return &wardenV1.UpdateSecretResponse{
		Secret: s.secretRepo.ToProto(secretEntity),
	}, nil
}

// UpdateSecretPassword updates the password (creates new version)
func (s *SecretService) UpdateSecretPassword(ctx context.Context, req *wardenV1.UpdateSecretPasswordRequest) (*wardenV1.UpdateSecretPasswordResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanWriteSecret(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to modify this secret")
	}

	secretEntity, err := s.secretRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if secretEntity == nil {
		return nil, wardenV1.ErrorSecretNotFound("secret not found")
	}

	// Store new password in Vault (creates new version)
	newVersion, err := s.kvStore.StorePassword(ctx, secretEntity.VaultPath, req.Password, nil)
	if err != nil {
		return nil, wardenV1.ErrorVaultOperationError("failed to store password")
	}

	// Create version record
	createdBy := getUserIDAsUint32(ctx)
	checksum := vault.CalculateChecksum(req.Password)
	versionEntity, err := s.versionRepo.Create(ctx, secretEntity.ID, int32(newVersion), secretEntity.VaultPath, req.Comment, checksum, createdBy)
	if err != nil {
		s.log.Warnf("failed to create version record: %v", err)
	}

	// Update secret's current version
	secretEntity, err = s.secretRepo.UpdateVersion(ctx, req.Id, int32(newVersion), createdBy)
	if err != nil {
		return nil, err
	}

	return &wardenV1.UpdateSecretPasswordResponse{
		Secret:  s.secretRepo.ToProto(secretEntity),
		Version: s.versionRepo.ToProto(versionEntity),
	}, nil
}

// DeleteSecret deletes a secret
func (s *SecretService) DeleteSecret(ctx context.Context, req *wardenV1.DeleteSecretRequest) (*emptypb.Empty, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanDeleteSecret(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to delete this secret")
	}

	secretEntity, err := s.secretRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if secretEntity == nil {
		return nil, wardenV1.ErrorSecretNotFound("secret not found")
	}

	if req.Permanent {
		// Delete from Vault
		if err := s.kvStore.DestroyAllVersions(ctx, secretEntity.VaultPath); err != nil {
			s.log.Warnf("failed to destroy password in Vault: %v", err)
		}

		// Delete version records
		if err := s.versionRepo.DeleteBySecretID(ctx, req.Id); err != nil {
			s.log.Warnf("failed to delete version records: %v", err)
		}
	}

	if err := s.secretRepo.Delete(ctx, req.Id, req.Permanent); err != nil {
		return nil, err
	}

	// Delete associated permissions
	_ = s.permRepo.DeleteByResource(ctx, tenantID, string(authz.ResourceTypeSecret), req.Id)

	return &emptypb.Empty{}, nil
}

// MoveSecret moves a secret to a different folder
func (s *SecretService) MoveSecret(ctx context.Context, req *wardenV1.MoveSecretRequest) (*wardenV1.MoveSecretResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission on source secret
	if err := s.checker.CanWriteSecret(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to move this secret")
	}

	// Check permission on destination folder (if specified)
	if req.NewFolderId != nil && *req.NewFolderId != "" {
		if err := s.checker.CanWriteFolder(ctx, tenantID, userID, *req.NewFolderId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to move secret to this folder")
		}
	}

	updatedBy := getUserIDAsUint32(ctx)
	secretEntity, err := s.secretRepo.Move(ctx, req.Id, req.NewFolderId, updatedBy)
	if err != nil {
		return nil, err
	}

	return &wardenV1.MoveSecretResponse{
		Secret: s.secretRepo.ToProto(secretEntity),
	}, nil
}

// ListVersions lists all versions of a secret
func (s *SecretService) ListVersions(ctx context.Context, req *wardenV1.ListVersionsRequest) (*wardenV1.ListVersionsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanReadSecret(ctx, tenantID, userID, req.SecretId); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to access this secret")
	}

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	versions, total, err := s.versionRepo.List(ctx, req.SecretId, page, pageSize)
	if err != nil {
		return nil, err
	}

	protoVersions := make([]*wardenV1.SecretVersion, 0, len(versions))
	for _, v := range versions {
		protoVersions = append(protoVersions, s.versionRepo.ToProto(v))
	}

	return &wardenV1.ListVersionsResponse{
		Versions: protoVersions,
		Total:    uint32(total),
	}, nil
}

// GetVersion gets a specific version
func (s *SecretService) GetVersion(ctx context.Context, req *wardenV1.GetVersionRequest) (*wardenV1.GetVersionResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanReadSecret(ctx, tenantID, userID, req.SecretId); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to access this secret")
	}

	versionEntity, err := s.versionRepo.GetBySecretAndVersion(ctx, req.SecretId, req.VersionNumber)
	if err != nil {
		return nil, err
	}
	if versionEntity == nil {
		return nil, wardenV1.ErrorVersionNotFound("version not found")
	}

	resp := &wardenV1.GetVersionResponse{
		Version: s.versionRepo.ToProto(versionEntity),
	}

	if req.IncludePassword {
		password, err := s.kvStore.GetPasswordVersion(ctx, versionEntity.VaultPath, int(req.VersionNumber))
		if err != nil {
			s.log.Warnf("failed to get password from Vault: %v", err)
		} else {
			resp.Password = &password
		}
	}

	return resp, nil
}

// RestoreVersion restores a previous version as current
func (s *SecretService) RestoreVersion(ctx context.Context, req *wardenV1.RestoreVersionRequest) (*wardenV1.RestoreVersionResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanWriteSecret(ctx, tenantID, userID, req.SecretId); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to modify this secret")
	}

	secretEntity, err := s.secretRepo.GetByID(ctx, req.SecretId)
	if err != nil {
		return nil, err
	}
	if secretEntity == nil {
		return nil, wardenV1.ErrorSecretNotFound("secret not found")
	}

	// Get the version to restore
	versionEntity, err := s.versionRepo.GetBySecretAndVersion(ctx, req.SecretId, req.VersionNumber)
	if err != nil {
		return nil, err
	}
	if versionEntity == nil {
		return nil, wardenV1.ErrorVersionNotFound("version not found")
	}

	// Get password from the version to restore
	password, err := s.kvStore.GetPasswordVersion(ctx, versionEntity.VaultPath, int(req.VersionNumber))
	if err != nil {
		return nil, wardenV1.ErrorVaultOperationError("failed to retrieve password from version")
	}

	// Create new version with the restored password
	newVersion, err := s.kvStore.StorePassword(ctx, secretEntity.VaultPath, password, nil)
	if err != nil {
		return nil, wardenV1.ErrorVaultOperationError("failed to store restored password")
	}

	// Create version record
	createdBy := getUserIDAsUint32(ctx)
	comment := req.Comment
	if comment == "" {
		comment = "Restored from version " + string(rune(req.VersionNumber))
	}
	checksum := vault.CalculateChecksum(password)
	newVersionEntity, err := s.versionRepo.Create(ctx, secretEntity.ID, int32(newVersion), secretEntity.VaultPath, comment, checksum, createdBy)
	if err != nil {
		s.log.Warnf("failed to create version record: %v", err)
	}

	// Update secret's current version
	secretEntity, err = s.secretRepo.UpdateVersion(ctx, req.SecretId, int32(newVersion), createdBy)
	if err != nil {
		return nil, err
	}

	return &wardenV1.RestoreVersionResponse{
		Secret:     s.secretRepo.ToProto(secretEntity),
		NewVersion: s.versionRepo.ToProto(newVersionEntity),
	}, nil
}

// SearchSecrets searches secrets across folders
func (s *SecretService) SearchSecrets(ctx context.Context, req *wardenV1.SearchSecretsRequest) (*wardenV1.SearchSecretsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	var status *secret.Status
	if req.Status != nil && *req.Status != wardenV1.SecretStatus_SECRET_STATUS_UNSPECIFIED {
		s := mapProtoStatusToEnt(*req.Status)
		status = &s
	}

	secrets, total, err := s.secretRepo.Search(ctx, tenantID, req.Query, req.FolderId, req.IncludeSubfolders, status, page, pageSize)
	if err != nil {
		return nil, err
	}

	// Filter secrets by permission
	accessibleSecrets := make([]*wardenV1.Secret, 0, len(secrets))
	for _, sec := range secrets {
		if err := s.checker.CanReadSecret(ctx, tenantID, userID, sec.ID); err == nil {
			accessibleSecrets = append(accessibleSecrets, s.secretRepo.ToProto(sec))
		}
	}

	return &wardenV1.SearchSecretsResponse{
		Secrets: accessibleSecrets,
		Total:   uint32(total),
	}, nil
}

// Helper functions

func mapProtoStatusToEnt(status wardenV1.SecretStatus) secret.Status {
	switch status {
	case wardenV1.SecretStatus_SECRET_STATUS_ACTIVE:
		return secret.StatusSECRET_STATUS_ACTIVE
	case wardenV1.SecretStatus_SECRET_STATUS_ARCHIVED:
		return secret.StatusSECRET_STATUS_ARCHIVED
	case wardenV1.SecretStatus_SECRET_STATUS_DELETED:
		return secret.StatusSECRET_STATUS_DELETED
	default:
		return secret.StatusSECRET_STATUS_UNSPECIFIED
	}
}

func generateUUID() string {
	return uuid.New().String()
}

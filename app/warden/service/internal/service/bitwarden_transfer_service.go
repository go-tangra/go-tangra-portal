package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/authz"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/pkg/vault"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
)

// BitwardenTransferService handles import/export of secrets in Bitwarden format
type BitwardenTransferService struct {
	wardenV1.UnimplementedWardenBitwardenTransferServiceServer

	log         *log.Helper
	secretRepo  *data.SecretRepo
	folderRepo  *data.FolderRepo
	versionRepo *data.SecretVersionRepo
	permRepo    *data.PermissionRepo
	kvStore     *vault.KVStore
	checker     *authz.Checker
}

// NewBitwardenTransferService creates a new BitwardenTransferService
func NewBitwardenTransferService(
	ctx *bootstrap.Context,
	secretRepo *data.SecretRepo,
	folderRepo *data.FolderRepo,
	versionRepo *data.SecretVersionRepo,
	permRepo *data.PermissionRepo,
	kvStore *vault.KVStore,
	checker *authz.Checker,
) *BitwardenTransferService {
	return &BitwardenTransferService{
		log:         ctx.NewLoggerHelper("warden/service/bitwarden-transfer"),
		secretRepo:  secretRepo,
		folderRepo:  folderRepo,
		versionRepo: versionRepo,
		permRepo:    permRepo,
		kvStore:     kvStore,
		checker:     checker,
	}
}

// bitwardenExportJSON represents the Bitwarden export file format
type bitwardenExportJSON struct {
	Encrypted bool                `json:"encrypted"`
	Folders   []bitwardenFolderJS `json:"folders"`
	Items     []bitwardenItemJSON `json:"items"`
}

type bitwardenFolderJS struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type bitwardenItemJSON struct {
	ID              string                       `json:"id"`
	FolderID        *string                      `json:"folderId,omitempty"`
	Type            int                          `json:"type"`
	Name            string                       `json:"name"`
	Notes           *string                      `json:"notes,omitempty"`
	Favorite        bool                         `json:"favorite"`
	Login           *bitwardenLoginJSON          `json:"login,omitempty"`
	Fields          []bitwardenFieldJSON         `json:"fields,omitempty"`
	PasswordHistory []bitwardenPasswordHistoryJS `json:"passwordHistory,omitempty"`
	CreationDate    string                       `json:"creationDate,omitempty"`
	RevisionDate    string                       `json:"revisionDate,omitempty"`
}

type bitwardenLoginJSON struct {
	URIs     []bitwardenURIJSON `json:"uris,omitempty"`
	Username string             `json:"username"`
	Password string             `json:"password"`
	TOTP     *string            `json:"totp,omitempty"`
}

type bitwardenURIJSON struct {
	URI   string `json:"uri"`
	Match *int   `json:"match,omitempty"`
}

type bitwardenFieldJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"`
}

type bitwardenPasswordHistoryJS struct {
	LastUsedDate string `json:"lastUsedDate"`
	Password     string `json:"password"`
}

// ExportToBitwarden exports secrets to Bitwarden JSON format
func (s *BitwardenTransferService) ExportToBitwarden(ctx context.Context, req *wardenV1.ExportToBitwardenRequest) (*wardenV1.ExportToBitwardenResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Build the export structure
	export := bitwardenExportJSON{
		Encrypted: false,
		Folders:   []bitwardenFolderJS{},
		Items:     []bitwardenItemJSON{},
	}

	// Track folder IDs for export
	folderIDSet := make(map[string]bool)

	// Get secrets based on filter
	var secrets []*ent.Secret
	var err error

	if req.FolderId != nil && *req.FolderId != "" {
		// Check permission on the folder
		if err := s.checker.CanReadFolder(ctx, tenantID, userID, *req.FolderId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to access this folder")
		}

		if req.IncludeSubfolders {
			// Get folder and all subfolders
			secrets, err = s.secretRepo.ListAllInFolderTree(ctx, tenantID, *req.FolderId)
		} else {
			// Get only secrets in this folder
			secretList, _, listErr := s.secretRepo.List(ctx, tenantID, req.FolderId, nil, nil, 1, 10000)
			if listErr != nil {
				return nil, listErr
			}
			secrets = secretList
		}
	} else {
		// Export all accessible secrets
		secrets, err = s.secretRepo.ListAll(ctx, tenantID)
	}

	if err != nil {
		return nil, err
	}

	// Filter by permission and export
	itemsExported := int32(0)
	itemsSkipped := int32(0)

	for _, secret := range secrets {
		// Check read permission
		if err := s.checker.CanReadSecret(ctx, tenantID, userID, secret.ID); err != nil {
			itemsSkipped++
			continue
		}

		// Track folder for export
		if secret.FolderID != nil && *secret.FolderID != "" {
			folderIDSet[*secret.FolderID] = true
		}

		// Get password from Vault
		password, _, err := s.kvStore.GetPassword(ctx, secret.VaultPath)
		if err != nil {
			s.log.Warnf("Failed to get password for secret %s: %v", secret.ID, err)
			itemsSkipped++
			continue
		}

		// Convert metadata to fields
		var fields []bitwardenFieldJSON
		if secret.Metadata != nil {
			for key, value := range secret.Metadata {
				fields = append(fields, bitwardenFieldJSON{
					Name:  key,
					Value: fmt.Sprintf("%v", value),
					Type:  0, // Text
				})
			}
		}

		// Build item
		item := bitwardenItemJSON{
			ID:       secret.ID,
			Type:     1, // Login type
			Name:     secret.Name,
			Favorite: false,
			Login: &bitwardenLoginJSON{
				Username: secret.Username,
				Password: password,
			},
			Fields: fields,
		}

		// Set creation/revision dates if available
		if secret.CreateTime != nil {
			item.CreationDate = secret.CreateTime.Format(time.RFC3339)
		}
		if secret.UpdateTime != nil {
			item.RevisionDate = secret.UpdateTime.Format(time.RFC3339)
		}

		// Add folder ID
		if secret.FolderID != nil && *secret.FolderID != "" {
			item.FolderID = secret.FolderID
		}

		// Add notes from description
		if secret.Description != "" {
			item.Notes = &secret.Description
		}

		// Add URI
		if secret.HostURL != "" {
			item.Login.URIs = []bitwardenURIJSON{
				{URI: secret.HostURL},
			}
		}

		export.Items = append(export.Items, item)
		itemsExported++
	}

	// Export folders
	for folderID := range folderIDSet {
		folder, err := s.folderRepo.GetByID(ctx, folderID)
		if err != nil || folder == nil {
			continue
		}
		export.Folders = append(export.Folders, bitwardenFolderJS{
			ID:   folder.ID,
			Name: folder.Path, // Use full path as name for proper hierarchy
		})
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, wardenV1.ErrorInternalServerError("failed to generate JSON")
	}

	// Generate filename
	filename := fmt.Sprintf("warden-export-%s.json", time.Now().Format("2006-01-02"))

	return &wardenV1.ExportToBitwardenResponse{
		JsonData:          string(jsonData),
		FoldersExported:   int32(len(export.Folders)),
		ItemsExported:     itemsExported,
		ItemsSkipped:      itemsSkipped,
		SuggestedFilename: filename,
	}, nil
}

// ImportFromBitwarden imports secrets from Bitwarden JSON format
func (s *BitwardenTransferService) ImportFromBitwarden(ctx context.Context, req *wardenV1.ImportFromBitwardenRequest) (*wardenV1.ImportFromBitwardenResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)
	createdBy := getUserIDAsUint32(ctx)

	// Parse JSON
	var export bitwardenExportJSON
	if err := json.Unmarshal([]byte(req.JsonData), &export); err != nil {
		return nil, wardenV1.ErrorInvalidFormat("invalid JSON format: " + err.Error())
	}

	// Check if encrypted (not supported)
	if export.Encrypted {
		return nil, wardenV1.ErrorInvalidFormat("encrypted exports are not supported, please export as unencrypted JSON")
	}

	// Validate target folder permission if specified
	if req.TargetFolderId != nil && *req.TargetFolderId != "" {
		if err := s.checker.CanWriteFolder(ctx, tenantID, userID, *req.TargetFolderId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to import into this folder")
		}
	}

	resp := &wardenV1.ImportFromBitwardenResponse{
		FolderIdMapping: make(map[string]string),
		ItemIdMapping:   make(map[string]string),
		Errors:          []*wardenV1.ImportError{},
	}

	// Import folders if preserving structure
	bitwardenToWardenFolder := make(map[string]string) // Bitwarden ID -> Warden ID

	if req.PreserveFolders {
		for _, bwFolder := range export.Folders {
			// Determine parent folder
			var parentID *string
			if req.TargetFolderId != nil && *req.TargetFolderId != "" {
				parentID = req.TargetFolderId
			}

			// Parse folder path to create nested structure
			folderName := bwFolder.Name
			if strings.Contains(bwFolder.Name, "/") {
				// Handle nested paths
				parts := strings.Split(bwFolder.Name, "/")
				folderName = parts[len(parts)-1]
			}

			// Create folder
			folder, err := s.folderRepo.Create(ctx, tenantID, parentID, folderName, "", createdBy)
			if err != nil {
				resp.Errors = append(resp.Errors, &wardenV1.ImportError{
					BitwardenId: bwFolder.ID,
					ItemName:    bwFolder.Name,
					ErrorType:   "folder_creation",
					Message:     err.Error(),
				})
				continue
			}

			bitwardenToWardenFolder[bwFolder.ID] = folder.ID
			resp.FolderIdMapping[bwFolder.ID] = folder.ID
			resp.FoldersCreated++

			// Grant owner permission
			if createdBy != nil {
				_, _ = s.permRepo.Create(ctx, tenantID, string(authz.ResourceTypeFolder), folder.ID, string(authz.RelationOwner), string(authz.SubjectTypeUser), userID, createdBy, nil)
			}
		}
	}

	// Get existing secret names for duplicate detection
	existingNames := make(map[string]bool)
	existingSecrets, _ := s.secretRepo.ListAll(ctx, tenantID)
	for _, sec := range existingSecrets {
		existingNames[strings.ToLower(sec.Name)] = true
	}

	// Import items
	for _, bwItem := range export.Items {
		// Only support login items
		if bwItem.Type != 1 {
			resp.Errors = append(resp.Errors, &wardenV1.ImportError{
				BitwardenId: bwItem.ID,
				ItemName:    bwItem.Name,
				ErrorType:   "unsupported_type",
				Message:     fmt.Sprintf("item type %d is not supported, only login items (type 1) are supported", bwItem.Type),
			})
			resp.ItemsSkipped++
			continue
		}

		// Skip items without login data
		if bwItem.Login == nil {
			resp.Errors = append(resp.Errors, &wardenV1.ImportError{
				BitwardenId: bwItem.ID,
				ItemName:    bwItem.Name,
				ErrorType:   "validation",
				Message:     "item has no login data",
			})
			resp.ItemsSkipped++
			continue
		}

		// Check for duplicates
		name := bwItem.Name
		nameLower := strings.ToLower(name)

		if existingNames[nameLower] {
			switch req.DuplicateHandling {
			case wardenV1.DuplicateHandling_DUPLICATE_HANDLING_SKIP:
				resp.Errors = append(resp.Errors, &wardenV1.ImportError{
					BitwardenId: bwItem.ID,
					ItemName:    bwItem.Name,
					ErrorType:   "duplicate",
					Message:     "item with same name already exists",
				})
				resp.ItemsSkipped++
				continue
			case wardenV1.DuplicateHandling_DUPLICATE_HANDLING_RENAME:
				// Find unique name
				counter := 1
				for existingNames[strings.ToLower(name)] {
					name = fmt.Sprintf("%s (%d)", bwItem.Name, counter)
					counter++
				}
			case wardenV1.DuplicateHandling_DUPLICATE_HANDLING_OVERWRITE:
				// TODO: Implement overwrite logic
				// For now, treat as rename
				counter := 1
				for existingNames[strings.ToLower(name)] {
					name = fmt.Sprintf("%s (%d)", bwItem.Name, counter)
					counter++
				}
			}
		}

		// Determine target folder
		var targetFolderID *string
		if req.PreserveFolders && bwItem.FolderID != nil {
			if wardenFolderID, ok := bitwardenToWardenFolder[*bwItem.FolderID]; ok {
				targetFolderID = &wardenFolderID
			}
		} else if req.TargetFolderId != nil && *req.TargetFolderId != "" {
			targetFolderID = req.TargetFolderId
		}

		// Extract host URL
		hostURL := ""
		if bwItem.Login.URIs != nil && len(bwItem.Login.URIs) > 0 {
			hostURL = bwItem.Login.URIs[0].URI
		}

		// Extract description
		description := ""
		if bwItem.Notes != nil {
			description = *bwItem.Notes
		}

		// Convert fields to metadata
		var metadata map[string]any
		if len(bwItem.Fields) > 0 {
			metadata = make(map[string]any)
			for _, field := range bwItem.Fields {
				metadata[field.Name] = field.Value
			}
		}

		// Create the secret
		secretID := uuid.New().String()
		vaultPath := s.kvStore.BuildPath(tenantID, secretID)

		// Store password in Vault
		_, err := s.kvStore.StorePassword(ctx, vaultPath, bwItem.Login.Password, nil)
		if err != nil {
			resp.Errors = append(resp.Errors, &wardenV1.ImportError{
				BitwardenId: bwItem.ID,
				ItemName:    bwItem.Name,
				ErrorType:   "vault_error",
				Message:     "failed to store password in vault: " + err.Error(),
			})
			resp.ItemsFailed++
			continue
		}

		// Create secret in database
		secret, err := s.secretRepo.Create(ctx, tenantID, targetFolderID, name, bwItem.Login.Username, hostURL, vaultPath, description, metadata, createdBy)
		if err != nil {
			// Cleanup Vault on failure
			_ = s.kvStore.DestroyAllVersions(ctx, vaultPath)
			resp.Errors = append(resp.Errors, &wardenV1.ImportError{
				BitwardenId: bwItem.ID,
				ItemName:    bwItem.Name,
				ErrorType:   "creation_error",
				Message:     err.Error(),
			})
			resp.ItemsFailed++
			continue
		}

		// Create initial version record
		checksum := vault.CalculateChecksum(bwItem.Login.Password)
		_, _ = s.versionRepo.Create(ctx, secret.ID, 1, vaultPath, "Imported from Bitwarden", checksum, createdBy)

		// Grant owner permission
		if createdBy != nil {
			_, _ = s.permRepo.Create(ctx, tenantID, string(authz.ResourceTypeSecret), secret.ID, string(authz.RelationOwner), string(authz.SubjectTypeUser), userID, createdBy, nil)
		}

		resp.ItemIdMapping[bwItem.ID] = secret.ID
		existingNames[strings.ToLower(name)] = true
		resp.ItemsImported++
	}

	return resp, nil
}

// ValidateBitwardenImport validates a Bitwarden import without making changes
func (s *BitwardenTransferService) ValidateBitwardenImport(ctx context.Context, req *wardenV1.ValidateBitwardenImportRequest) (*wardenV1.ValidateBitwardenImportResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	resp := &wardenV1.ValidateBitwardenImportResponse{
		IsValid:        true,
		Warnings:       []string{},
		Errors:         []string{},
		DuplicateNames: []string{},
	}

	// Validate target folder permission if specified
	if req.TargetFolderId != nil && *req.TargetFolderId != "" {
		if err := s.checker.CanWriteFolder(ctx, tenantID, userID, *req.TargetFolderId); err != nil {
			resp.IsValid = false
			resp.Errors = append(resp.Errors, "no permission to import into the specified folder")
			return resp, nil
		}
	}

	// Parse JSON
	var export bitwardenExportJSON
	if err := json.Unmarshal([]byte(req.JsonData), &export); err != nil {
		resp.IsValid = false
		resp.Errors = append(resp.Errors, "Invalid JSON format: "+err.Error())
		return resp, nil
	}

	// Check if encrypted
	if export.Encrypted {
		resp.IsValid = false
		resp.Errors = append(resp.Errors, "Encrypted exports are not supported")
		return resp, nil
	}

	resp.FoldersFound = int32(len(export.Folders))

	// Count item types
	for _, item := range export.Items {
		if item.Type == 1 {
			resp.LoginItemsFound++
		} else {
			resp.OtherItemsFound++
		}
	}

	// Check for unsupported types
	if resp.OtherItemsFound > 0 {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("%d items are not login type and will be skipped", resp.OtherItemsFound))
	}

	// Get existing secret names for duplicate detection
	existingNames := make(map[string]bool)
	existingSecrets, _ := s.secretRepo.ListAll(ctx, tenantID)
	for _, sec := range existingSecrets {
		existingNames[strings.ToLower(sec.Name)] = true
	}

	// Check for duplicates
	for _, item := range export.Items {
		if item.Type != 1 {
			continue
		}
		if existingNames[strings.ToLower(item.Name)] {
			resp.DuplicateNames = append(resp.DuplicateNames, item.Name)
		}
	}

	if len(resp.DuplicateNames) > 0 {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("%d items have names that already exist", len(resp.DuplicateNames)))
	}

	// Validate items
	for _, item := range export.Items {
		if item.Type == 1 && item.Login == nil {
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("Item '%s' is a login type but has no login data", item.Name))
		}
		if item.Name == "" {
			resp.Errors = append(resp.Errors, fmt.Sprintf("Item with ID '%s' has no name", item.ID))
			resp.IsValid = false
		}
	}

	return resp, nil
}

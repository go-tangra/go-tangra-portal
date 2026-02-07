package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/authz"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
)

type FolderService struct {
	wardenV1.UnimplementedWardenFolderServiceServer

	log        *log.Helper
	folderRepo *data.FolderRepo
	permRepo   *data.PermissionRepo
	checker    *authz.Checker
}

func NewFolderService(
	ctx *bootstrap.Context,
	folderRepo *data.FolderRepo,
	permRepo *data.PermissionRepo,
	checker *authz.Checker,
) *FolderService {
	return &FolderService{
		log:        ctx.NewLoggerHelper("warden/service/folder"),
		folderRepo: folderRepo,
		permRepo:   permRepo,
		checker:    checker,
	}
}

// CreateFolder creates a new folder
func (s *FolderService) CreateFolder(ctx context.Context, req *wardenV1.CreateFolderRequest) (*wardenV1.CreateFolderResponse, error) {
	// Get tenant and user from context
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission on parent folder (if specified)
	if req.ParentId != nil && *req.ParentId != "" {
		if err := s.checker.CanWriteFolder(ctx, tenantID, userID, *req.ParentId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to create folder in this location")
		}
	}

	// Create folder
	createdBy := getUserIDAsUint32(ctx)
	folder, err := s.folderRepo.Create(ctx, tenantID, req.ParentId, req.Name, req.Description, createdBy)
	if err != nil {
		return nil, err
	}

	// Grant owner permission to creator
	if createdBy != nil {
		_, err = s.permRepo.Create(ctx, tenantID, string(authz.ResourceTypeFolder), folder.ID, string(authz.RelationOwner), string(authz.SubjectTypeUser), userID, createdBy, nil)
		if err != nil {
			s.log.Warnf("failed to grant owner permission: %v", err)
		}
	}

	return &wardenV1.CreateFolderResponse{
		Folder: s.folderRepo.ToProto(folder),
	}, nil
}

// GetFolder gets a folder by ID
func (s *FolderService) GetFolder(ctx context.Context, req *wardenV1.GetFolderRequest) (*wardenV1.GetFolderResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanReadFolder(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to access this folder")
	}

	folder, err := s.folderRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if folder == nil {
		return nil, wardenV1.ErrorFolderNotFound("folder not found")
	}

	var folderProto *wardenV1.Folder
	if req.IncludeCounts {
		folderProto, err = s.folderRepo.ToProtoWithCounts(ctx, folder)
		if err != nil {
			return nil, err
		}
	} else {
		folderProto = s.folderRepo.ToProto(folder)
	}

	return &wardenV1.GetFolderResponse{
		Folder: folderProto,
	}, nil
}

// ListFolders lists folders
func (s *FolderService) ListFolders(ctx context.Context, req *wardenV1.ListFoldersRequest) (*wardenV1.ListFoldersResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// If parent is specified, check permission on parent
	if req.ParentId != nil && *req.ParentId != "" {
		if err := s.checker.CanReadFolder(ctx, tenantID, userID, *req.ParentId); err != nil {
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

	folders, total, err := s.folderRepo.List(ctx, tenantID, req.ParentId, req.NameFilter, page, pageSize)
	if err != nil {
		return nil, err
	}

	// Filter folders by permission
	accessibleFolders := make([]*wardenV1.Folder, 0, len(folders))
	for _, folder := range folders {
		if err := s.checker.CanReadFolder(ctx, tenantID, userID, folder.ID); err == nil {
			accessibleFolders = append(accessibleFolders, s.folderRepo.ToProto(folder))
		}
	}

	return &wardenV1.ListFoldersResponse{
		Folders: accessibleFolders,
		Total:   uint32(total),
	}, nil
}

// UpdateFolder updates folder metadata
func (s *FolderService) UpdateFolder(ctx context.Context, req *wardenV1.UpdateFolderRequest) (*wardenV1.UpdateFolderResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanWriteFolder(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to modify this folder")
	}

	folder, err := s.folderRepo.Update(ctx, req.Id, req.Name, req.Description)
	if err != nil {
		return nil, err
	}

	return &wardenV1.UpdateFolderResponse{
		Folder: s.folderRepo.ToProto(folder),
	}, nil
}

// DeleteFolder deletes a folder
func (s *FolderService) DeleteFolder(ctx context.Context, req *wardenV1.DeleteFolderRequest) (*emptypb.Empty, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission
	if err := s.checker.CanDeleteFolder(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to delete this folder")
	}

	if err := s.folderRepo.Delete(ctx, req.Id, req.Force); err != nil {
		return nil, err
	}

	// Delete associated permissions
	_ = s.permRepo.DeleteByResource(ctx, tenantID, string(authz.ResourceTypeFolder), req.Id)

	return &emptypb.Empty{}, nil
}

// MoveFolder moves a folder to a new parent
func (s *FolderService) MoveFolder(ctx context.Context, req *wardenV1.MoveFolderRequest) (*wardenV1.MoveFolderResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission on source folder
	if err := s.checker.CanWriteFolder(ctx, tenantID, userID, req.Id); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to move this folder")
	}

	// Check permission on destination folder (if specified)
	if req.NewParentId != nil && *req.NewParentId != "" {
		if err := s.checker.CanWriteFolder(ctx, tenantID, userID, *req.NewParentId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to move folder to this location")
		}
	}

	folder, err := s.folderRepo.Move(ctx, req.Id, req.NewParentId)
	if err != nil {
		return nil, err
	}

	return &wardenV1.MoveFolderResponse{
		Folder: s.folderRepo.ToProto(folder),
	}, nil
}

// GetFolderTree gets the folder tree structure
func (s *FolderService) GetFolderTree(ctx context.Context, req *wardenV1.GetFolderTreeRequest) (*wardenV1.GetFolderTreeResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check permission on root folder (if specified)
	if req.RootId != nil && *req.RootId != "" {
		if err := s.checker.CanReadFolder(ctx, tenantID, userID, *req.RootId); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to access this folder")
		}
	}

	maxDepth := int32(10)
	if req.MaxDepth != nil {
		maxDepth = *req.MaxDepth
	}

	roots, err := s.folderRepo.BuildTree(ctx, tenantID, req.RootId, maxDepth, req.IncludeCounts)
	if err != nil {
		return nil, err
	}

	return &wardenV1.GetFolderTreeResponse{
		Roots: roots,
	}, nil
}

// Helper functions to extract context values
func getTenantIDFromContext(ctx context.Context) uint32 {
	// TODO: Implement proper context extraction
	return 1
}

func getUserIDFromContext(ctx context.Context) string {
	// TODO: Implement proper context extraction
	return "1"
}

func getUserIDAsUint32(ctx context.Context) *uint32 {
	// TODO: Implement proper context extraction
	id := uint32(1)
	return &id
}

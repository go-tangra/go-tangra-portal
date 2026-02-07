package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data"

	paperlessV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/paperless/service/v1"
)

type CategoryService struct {
	paperlessV1.UnimplementedPaperlessCategoryServiceServer

	log          *log.Helper
	categoryRepo *data.CategoryRepo
	permRepo     *data.PermissionRepo
}

func NewCategoryService(
	ctx *bootstrap.Context,
	categoryRepo *data.CategoryRepo,
	permRepo *data.PermissionRepo,
) *CategoryService {
	return &CategoryService{
		log:          ctx.NewLoggerHelper("paperless/service/category"),
		categoryRepo: categoryRepo,
		permRepo:     permRepo,
	}
}

// CreateCategory creates a new category
func (s *CategoryService) CreateCategory(ctx context.Context, req *paperlessV1.CreateCategoryRequest) (*paperlessV1.CreateCategoryResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	createdBy := getUserIDAsUint32(ctx)
	userID := getUserIDFromContext(ctx)

	// Create category
	category, err := s.categoryRepo.Create(ctx, tenantID, req.ParentId, req.Name, req.Description, req.SortOrder, createdBy)
	if err != nil {
		return nil, err
	}

	// Grant owner permission to creator
	if createdBy != nil {
		_, err = s.permRepo.Create(ctx, tenantID, "RESOURCE_TYPE_CATEGORY", category.ID, "RELATION_OWNER", "SUBJECT_TYPE_USER", userID, createdBy, nil)
		if err != nil {
			s.log.Warnf("failed to grant owner permission: %v", err)
		}
	}

	return &paperlessV1.CreateCategoryResponse{
		Category: s.categoryRepo.ToProto(category),
	}, nil
}

// GetCategory gets a category by ID
func (s *CategoryService) GetCategory(ctx context.Context, req *paperlessV1.GetCategoryRequest) (*paperlessV1.GetCategoryResponse, error) {
	category, err := s.categoryRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if category == nil {
		return nil, paperlessV1.ErrorCategoryNotFound("category not found")
	}

	var categoryProto *paperlessV1.Category
	if req.IncludeCounts {
		categoryProto, err = s.categoryRepo.ToProtoWithCounts(ctx, category)
		if err != nil {
			return nil, err
		}
	} else {
		categoryProto = s.categoryRepo.ToProto(category)
	}

	return &paperlessV1.GetCategoryResponse{
		Category: categoryProto,
	}, nil
}

// ListCategories lists categories
func (s *CategoryService) ListCategories(ctx context.Context, req *paperlessV1.ListCategoriesRequest) (*paperlessV1.ListCategoriesResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	categories, total, err := s.categoryRepo.List(ctx, tenantID, req.ParentId, req.NameFilter, page, pageSize)
	if err != nil {
		return nil, err
	}

	protoCategories := make([]*paperlessV1.Category, 0, len(categories))
	for _, category := range categories {
		protoCategories = append(protoCategories, s.categoryRepo.ToProto(category))
	}

	return &paperlessV1.ListCategoriesResponse{
		Categories: protoCategories,
		Total:      uint32(total),
	}, nil
}

// UpdateCategory updates category metadata
func (s *CategoryService) UpdateCategory(ctx context.Context, req *paperlessV1.UpdateCategoryRequest) (*paperlessV1.UpdateCategoryResponse, error) {
	category, err := s.categoryRepo.Update(ctx, req.Id, req.Name, req.Description, req.SortOrder)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.UpdateCategoryResponse{
		Category: s.categoryRepo.ToProto(category),
	}, nil
}

// DeleteCategory deletes a category
func (s *CategoryService) DeleteCategory(ctx context.Context, req *paperlessV1.DeleteCategoryRequest) (*emptypb.Empty, error) {
	tenantID := getTenantIDFromContext(ctx)

	if err := s.categoryRepo.Delete(ctx, req.Id, req.Force); err != nil {
		return nil, err
	}

	// Delete associated permissions
	_ = s.permRepo.DeleteByResource(ctx, tenantID, "RESOURCE_TYPE_CATEGORY", req.Id)

	return &emptypb.Empty{}, nil
}

// MoveCategory moves a category to a new parent
func (s *CategoryService) MoveCategory(ctx context.Context, req *paperlessV1.MoveCategoryRequest) (*paperlessV1.MoveCategoryResponse, error) {
	category, err := s.categoryRepo.Move(ctx, req.Id, req.NewParentId)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.MoveCategoryResponse{
		Category: s.categoryRepo.ToProto(category),
	}, nil
}

// GetCategoryTree gets the category tree structure
func (s *CategoryService) GetCategoryTree(ctx context.Context, req *paperlessV1.GetCategoryTreeRequest) (*paperlessV1.GetCategoryTreeResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	maxDepth := int32(10)
	if req.MaxDepth != nil {
		maxDepth = *req.MaxDepth
	}

	roots, err := s.categoryRepo.BuildTree(ctx, tenantID, req.RootId, maxDepth, req.IncludeCounts)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.GetCategoryTreeResponse{
		Roots: roots,
	}, nil
}

// Helper functions to extract context values
func getTenantIDFromContext(ctx context.Context) uint32 {
	// TODO: Implement proper context extraction from metadata
	return 1
}

func getUserIDFromContext(ctx context.Context) string {
	// TODO: Implement proper context extraction from metadata
	return "1"
}

func getUserIDAsUint32(ctx context.Context) *uint32 {
	// TODO: Implement proper context extraction from metadata
	id := uint32(1)
	return &id
}

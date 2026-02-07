package data

import (
	"context"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data/ent/category"
	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data/ent/document"

	paperlessV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/paperless/service/v1"
)

// derefUint32 safely dereferences a uint32 pointer, returning 0 if nil
func derefUint32(p *uint32) uint32 {
	if p == nil {
		return 0
	}
	return *p
}

type CategoryRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewCategoryRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *CategoryRepo {
	return &CategoryRepo{
		log:       ctx.NewLoggerHelper("paperless/category/repo"),
		entClient: entClient,
	}
}

// Create creates a new category
func (r *CategoryRepo) Create(ctx context.Context, tenantID uint32, parentID *string, name, description string, sortOrder int32, createdBy *uint32) (*ent.Category, error) {
	id := uuid.New().String()

	// Build path and calculate depth
	path := "/" + name
	depth := int32(0)

	if parentID != nil && *parentID != "" {
		parent, err := r.GetByID(ctx, *parentID)
		if err != nil {
			return nil, err
		}
		if parent == nil {
			return nil, paperlessV1.ErrorCategoryNotFound("parent category not found")
		}
		path = parent.Path + "/" + name
		depth = parent.Depth + 1
	}

	builder := r.entClient.Client().Category.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetPath(path).
		SetDepth(depth).
		SetSortOrder(sortOrder).
		SetCreateTime(time.Now())

	if parentID != nil && *parentID != "" {
		builder.SetParentID(*parentID)
	}
	if description != "" {
		builder.SetDescription(description)
	}
	if createdBy != nil {
		builder.SetCreateBy(*createdBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, paperlessV1.ErrorCategoryAlreadyExists("category already exists")
		}
		r.log.Errorf("create category failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("create category failed")
	}

	return entity, nil
}

// GetByID retrieves a category by ID
func (r *CategoryRepo) GetByID(ctx context.Context, id string) (*ent.Category, error) {
	entity, err := r.entClient.Client().Category.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get category failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("get category failed")
	}
	return entity, nil
}

// GetByTenantAndPath retrieves a category by tenant ID and path
func (r *CategoryRepo) GetByTenantAndPath(ctx context.Context, tenantID uint32, path string) (*ent.Category, error) {
	entity, err := r.entClient.Client().Category.Query().
		Where(
			category.TenantIDEQ(tenantID),
			category.PathEQ(path),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get category by path failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("get category failed")
	}
	return entity, nil
}

// List lists categories with optional parent filter
func (r *CategoryRepo) List(ctx context.Context, tenantID uint32, parentID *string, nameFilter *string, page, pageSize uint32) ([]*ent.Category, int, error) {
	query := r.entClient.Client().Category.Query().
		Where(category.TenantIDEQ(tenantID))

	if parentID != nil {
		if *parentID == "" {
			// Root-level categories (no parent)
			query = query.Where(category.ParentIDIsNil())
		} else {
			query = query.Where(category.ParentIDEQ(*parentID))
		}
	}

	if nameFilter != nil && *nameFilter != "" {
		query = query.Where(category.NameContains(*nameFilter))
	}

	// Count total
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count categories failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("count categories failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		query = query.Offset(offset).Limit(int(pageSize))
	}

	entities, err := query.Order(ent.Asc(category.FieldSortOrder), ent.Asc(category.FieldName)).All(ctx)
	if err != nil {
		r.log.Errorf("list categories failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("list categories failed")
	}

	return entities, total, nil
}

// ListByParentID lists child categories
func (r *CategoryRepo) ListByParentID(ctx context.Context, tenantID uint32, parentID string) ([]*ent.Category, error) {
	entities, err := r.entClient.Client().Category.Query().
		Where(
			category.TenantIDEQ(tenantID),
			category.ParentIDEQ(parentID),
		).
		Order(ent.Asc(category.FieldSortOrder), ent.Asc(category.FieldName)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list child categories failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("list child categories failed")
	}
	return entities, nil
}

// Update updates a category
func (r *CategoryRepo) Update(ctx context.Context, id string, name, description *string, sortOrder *int32) (*ent.Category, error) {
	builder := r.entClient.Client().Category.UpdateOneID(id).
		SetUpdateTime(time.Now())

	if name != nil {
		builder.SetName(*name)
	}
	if description != nil {
		builder.SetDescription(*description)
	}
	if sortOrder != nil {
		builder.SetSortOrder(*sortOrder)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, paperlessV1.ErrorCategoryNotFound("category not found")
		}
		if ent.IsConstraintError(err) {
			return nil, paperlessV1.ErrorCategoryAlreadyExists("category with this name already exists")
		}
		r.log.Errorf("update category failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("update category failed")
	}

	return entity, nil
}

// Move moves a category to a new parent
func (r *CategoryRepo) Move(ctx context.Context, id string, newParentID *string) (*ent.Category, error) {
	// Get the category
	c, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, paperlessV1.ErrorCategoryNotFound("category not found")
	}

	// Calculate new path and depth
	newPath := "/" + c.Name
	newDepth := int32(0)

	if newParentID != nil && *newParentID != "" {
		// Check for circular reference
		if *newParentID == id {
			return nil, paperlessV1.ErrorCircularCategoryReference("cannot move category to itself")
		}

		parent, err := r.GetByID(ctx, *newParentID)
		if err != nil {
			return nil, err
		}
		if parent == nil {
			return nil, paperlessV1.ErrorCategoryNotFound("new parent category not found")
		}

		// Check if new parent is a descendant of the category being moved
		if strings.HasPrefix(parent.Path, c.Path+"/") {
			return nil, paperlessV1.ErrorCircularCategoryReference("cannot move category to its own descendant")
		}

		newPath = parent.Path + "/" + c.Name
		newDepth = parent.Depth + 1
	}

	// Update category
	builder := r.entClient.Client().Category.UpdateOneID(id).
		SetPath(newPath).
		SetDepth(newDepth).
		SetUpdateTime(time.Now())

	if newParentID != nil && *newParentID != "" {
		builder.SetParentID(*newParentID)
	} else {
		builder.ClearParentID()
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, paperlessV1.ErrorCategoryAlreadyExists("category with this name already exists in the destination")
		}
		r.log.Errorf("move category failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("move category failed")
	}

	// Update paths of all descendant categories
	if err := r.updateDescendantPaths(ctx, *c.TenantID, c.Path, newPath); err != nil {
		r.log.Errorf("update descendant paths failed: %s", err.Error())
	}

	return entity, nil
}

// updateDescendantPaths updates paths of all categories under a path
func (r *CategoryRepo) updateDescendantPaths(ctx context.Context, tenantID uint32, oldPathPrefix, newPathPrefix string) error {
	descendants, err := r.entClient.Client().Category.Query().
		Where(
			category.TenantIDEQ(tenantID),
			category.PathHasPrefix(oldPathPrefix+"/"),
		).
		All(ctx)
	if err != nil {
		return err
	}

	for _, d := range descendants {
		newPath := strings.Replace(d.Path, oldPathPrefix, newPathPrefix, 1)
		_, err := r.entClient.Client().Category.UpdateOneID(d.ID).
			SetPath(newPath).
			SetUpdateTime(time.Now()).
			Save(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete deletes a category
func (r *CategoryRepo) Delete(ctx context.Context, id string, force bool) error {
	// Check if category has children
	childCount, err := r.entClient.Client().Category.Query().
		Where(category.ParentIDEQ(id)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count child categories failed: %s", err.Error())
		return paperlessV1.ErrorInternalServerError("delete category failed")
	}
	if childCount > 0 && !force {
		return paperlessV1.ErrorCategoryNotEmpty("category has child categories")
	}

	// Check if category has active documents (excluding deleted ones)
	documentCount, err := r.entClient.Client().Document.Query().
		Where(
			document.CategoryIDEQ(id),
			document.StatusNEQ(document.StatusDOCUMENT_STATUS_DELETED),
		).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count documents failed: %s", err.Error())
		return paperlessV1.ErrorInternalServerError("delete category failed")
	}
	if documentCount > 0 && !force {
		return paperlessV1.ErrorCategoryNotEmpty("category contains documents")
	}

	if force {
		// Delete all descendants recursively
		c, err := r.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if c != nil {
			// Delete all descendant categories
			_, err = r.entClient.Client().Category.Delete().
				Where(category.PathHasPrefix(c.Path + "/")).
				Exec(ctx)
			if err != nil {
				r.log.Errorf("delete descendant categories failed: %s", err.Error())
				return paperlessV1.ErrorInternalServerError("delete category failed")
			}
		}
	}

	err = r.entClient.Client().Category.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return paperlessV1.ErrorCategoryNotFound("category not found")
		}
		r.log.Errorf("delete category failed: %s", err.Error())
		return paperlessV1.ErrorInternalServerError("delete category failed")
	}
	return nil
}

// CountDocuments counts documents in a category
func (r *CategoryRepo) CountDocuments(ctx context.Context, categoryID string) (int, error) {
	count, err := r.entClient.Client().Document.Query().
		Where(document.CategoryIDEQ(categoryID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count documents failed: %s", err.Error())
		return 0, paperlessV1.ErrorInternalServerError("count documents failed")
	}
	return count, nil
}

// CountSubcategories counts subcategories in a category
func (r *CategoryRepo) CountSubcategories(ctx context.Context, categoryID string) (int, error) {
	count, err := r.entClient.Client().Category.Query().
		Where(category.ParentIDEQ(categoryID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count subcategories failed: %s", err.Error())
		return 0, paperlessV1.ErrorInternalServerError("count subcategories failed")
	}
	return count, nil
}

// GetCategoryParentID returns the parent category ID
func (r *CategoryRepo) GetCategoryParentID(ctx context.Context, tenantID uint32, categoryID string) (*string, error) {
	c, err := r.GetByID(ctx, categoryID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, nil
	}
	return c.ParentID, nil
}

// ToProto converts an ent.Category to paperlessV1.Category
func (r *CategoryRepo) ToProto(entity *ent.Category) *paperlessV1.Category {
	if entity == nil {
		return nil
	}

	proto := &paperlessV1.Category{
		Id:          entity.ID,
		TenantId:    derefUint32(entity.TenantID),
		Name:        entity.Name,
		Path:        entity.Path,
		Description: entity.Description,
		Depth:       entity.Depth,
		SortOrder:   entity.SortOrder,
	}

	if entity.ParentID != nil {
		proto.ParentId = entity.ParentID
	}
	if entity.CreateBy != nil {
		proto.CreatedBy = entity.CreateBy
	}
	if entity.CreateTime != nil && !entity.CreateTime.IsZero() {
		proto.CreateTime = timestamppb.New(*entity.CreateTime)
	}
	if entity.UpdateTime != nil && !entity.UpdateTime.IsZero() {
		proto.UpdateTime = timestamppb.New(*entity.UpdateTime)
	}

	return proto
}

// ToProtoWithCounts converts an ent.Category to paperlessV1.Category with counts
func (r *CategoryRepo) ToProtoWithCounts(ctx context.Context, entity *ent.Category) (*paperlessV1.Category, error) {
	proto := r.ToProto(entity)
	if proto == nil {
		return nil, nil
	}

	documentCount, err := r.CountDocuments(ctx, entity.ID)
	if err != nil {
		return nil, err
	}
	proto.DocumentCount = int32(documentCount)

	subcategoryCount, err := r.CountSubcategories(ctx, entity.ID)
	if err != nil {
		return nil, err
	}
	proto.SubcategoryCount = int32(subcategoryCount)

	return proto, nil
}

// BuildTree builds a category tree starting from root categories or a specific category
func (r *CategoryRepo) BuildTree(ctx context.Context, tenantID uint32, rootID *string, maxDepth int32, includeCounts bool) ([]*paperlessV1.CategoryTreeNode, error) {
	var roots []*ent.Category
	var err error

	if rootID != nil && *rootID != "" {
		root, err := r.GetByID(ctx, *rootID)
		if err != nil {
			return nil, err
		}
		if root == nil {
			return nil, paperlessV1.ErrorCategoryNotFound("root category not found")
		}
		roots = []*ent.Category{root}
	} else {
		roots, err = r.entClient.Client().Category.Query().
			Where(
				category.TenantIDEQ(tenantID),
				category.ParentIDIsNil(),
			).
			Order(ent.Asc(category.FieldSortOrder), ent.Asc(category.FieldName)).
			All(ctx)
		if err != nil {
			r.log.Errorf("get root categories failed: %s", err.Error())
			return nil, paperlessV1.ErrorInternalServerError("get category tree failed")
		}
	}

	nodes := make([]*paperlessV1.CategoryTreeNode, 0, len(roots))
	for _, root := range roots {
		node, err := r.buildTreeNode(ctx, root, 0, maxDepth, includeCounts)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

func (r *CategoryRepo) buildTreeNode(ctx context.Context, c *ent.Category, currentDepth, maxDepth int32, includeCounts bool) (*paperlessV1.CategoryTreeNode, error) {
	var categoryProto *paperlessV1.Category
	var err error

	if includeCounts {
		categoryProto, err = r.ToProtoWithCounts(ctx, c)
		if err != nil {
			return nil, err
		}
	} else {
		categoryProto = r.ToProto(c)
	}

	node := &paperlessV1.CategoryTreeNode{
		Category: categoryProto,
		Children: make([]*paperlessV1.CategoryTreeNode, 0),
	}

	// Check if we should continue building the tree
	if maxDepth > 0 && currentDepth >= maxDepth {
		return node, nil
	}

	// Get children
	children, err := r.ListByParentID(ctx, *c.TenantID, c.ID)
	if err != nil {
		return nil, err
	}

	for _, child := range children {
		childNode, err := r.buildTreeNode(ctx, child, currentDepth+1, maxDepth, includeCounts)
		if err != nil {
			return nil, err
		}
		node.Children = append(node.Children, childNode)
	}

	return node, nil
}

// GetAllDescendantIDs returns all descendant category IDs
func (r *CategoryRepo) GetAllDescendantIDs(ctx context.Context, tenantID uint32, categoryID string) ([]string, error) {
	c, err := r.GetByID(ctx, categoryID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, nil
	}

	descendants, err := r.entClient.Client().Category.Query().
		Where(
			category.TenantIDEQ(tenantID),
			category.PathHasPrefix(c.Path+"/"),
		).
		Select(category.FieldID).
		All(ctx)
	if err != nil {
		r.log.Errorf("get descendant categories failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("get descendant categories failed")
	}

	ids := make([]string, 0, len(descendants))
	for _, d := range descendants {
		ids = append(ids, d.ID)
	}

	return ids, nil
}

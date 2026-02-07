package data

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent/folder"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent/secret"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
)

// derefUint32 safely dereferences a uint32 pointer, returning 0 if nil
func derefUint32(p *uint32) uint32 {
	if p == nil {
		return 0
	}
	return *p
}

type FolderRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewFolderRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *FolderRepo {
	return &FolderRepo{
		log:       ctx.NewLoggerHelper("folder/repo"),
		entClient: entClient,
	}
}

// Create creates a new folder
func (r *FolderRepo) Create(ctx context.Context, tenantID uint32, parentID *string, name, description string, createdBy *uint32) (*ent.Folder, error) {
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
			return nil, wardenV1.ErrorFolderNotFound("parent folder not found")
		}
		path = parent.Path + "/" + name
		depth = parent.Depth + 1
	}

	builder := r.entClient.Client().Folder.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetPath(path).
		SetDepth(depth).
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
			return nil, wardenV1.ErrorFolderAlreadyExists("folder already exists")
		}
		r.log.Errorf("create folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("create folder failed")
	}

	return entity, nil
}

// GetByID retrieves a folder by ID
func (r *FolderRepo) GetByID(ctx context.Context, id string) (*ent.Folder, error) {
	entity, err := r.entClient.Client().Folder.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get folder failed")
	}
	return entity, nil
}

// GetByTenantAndPath retrieves a folder by tenant ID and path
func (r *FolderRepo) GetByTenantAndPath(ctx context.Context, tenantID uint32, path string) (*ent.Folder, error) {
	entity, err := r.entClient.Client().Folder.Query().
		Where(
			folder.TenantIDEQ(tenantID),
			folder.PathEQ(path),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get folder by path failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get folder failed")
	}
	return entity, nil
}

// List lists folders with optional parent filter
func (r *FolderRepo) List(ctx context.Context, tenantID uint32, parentID *string, nameFilter *string, page, pageSize uint32) ([]*ent.Folder, int, error) {
	query := r.entClient.Client().Folder.Query().
		Where(folder.TenantIDEQ(tenantID))

	if parentID != nil {
		if *parentID == "" {
			// Root-level folders (no parent)
			query = query.Where(folder.ParentIDIsNil())
		} else {
			query = query.Where(folder.ParentIDEQ(*parentID))
		}
	}

	if nameFilter != nil && *nameFilter != "" {
		query = query.Where(folder.NameContains(*nameFilter))
	}

	// Count total
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count folders failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("count folders failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		query = query.Offset(offset).Limit(int(pageSize))
	}

	entities, err := query.Order(ent.Asc(folder.FieldName)).All(ctx)
	if err != nil {
		r.log.Errorf("list folders failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("list folders failed")
	}

	return entities, total, nil
}

// ListByParentID lists child folders
func (r *FolderRepo) ListByParentID(ctx context.Context, tenantID uint32, parentID string) ([]*ent.Folder, error) {
	entities, err := r.entClient.Client().Folder.Query().
		Where(
			folder.TenantIDEQ(tenantID),
			folder.ParentIDEQ(parentID),
		).
		Order(ent.Asc(folder.FieldName)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list child folders failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("list child folders failed")
	}
	return entities, nil
}

// Update updates a folder
func (r *FolderRepo) Update(ctx context.Context, id string, name, description *string) (*ent.Folder, error) {
	builder := r.entClient.Client().Folder.UpdateOneID(id).
		SetUpdateTime(time.Now())

	if name != nil {
		builder.SetName(*name)
	}
	if description != nil {
		builder.SetDescription(*description)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, wardenV1.ErrorFolderNotFound("folder not found")
		}
		if ent.IsConstraintError(err) {
			return nil, wardenV1.ErrorFolderAlreadyExists("folder with this name already exists")
		}
		r.log.Errorf("update folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("update folder failed")
	}

	return entity, nil
}

// Move moves a folder to a new parent
func (r *FolderRepo) Move(ctx context.Context, id string, newParentID *string) (*ent.Folder, error) {
	// Get the folder
	f, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, wardenV1.ErrorFolderNotFound("folder not found")
	}

	// Calculate new path and depth
	newPath := "/" + f.Name
	newDepth := int32(0)

	if newParentID != nil && *newParentID != "" {
		// Check for circular reference
		if *newParentID == id {
			return nil, wardenV1.ErrorCircularFolderReference("cannot move folder to itself")
		}

		parent, err := r.GetByID(ctx, *newParentID)
		if err != nil {
			return nil, err
		}
		if parent == nil {
			return nil, wardenV1.ErrorFolderNotFound("new parent folder not found")
		}

		// Check if new parent is a descendant of the folder being moved
		if strings.HasPrefix(parent.Path, f.Path+"/") {
			return nil, wardenV1.ErrorCircularFolderReference("cannot move folder to its own descendant")
		}

		newPath = parent.Path + "/" + f.Name
		newDepth = parent.Depth + 1
	}

	// Update folder
	builder := r.entClient.Client().Folder.UpdateOneID(id).
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
			return nil, wardenV1.ErrorFolderAlreadyExists("folder with this name already exists in the destination")
		}
		r.log.Errorf("move folder failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("move folder failed")
	}

	// Update paths of all descendant folders
	if err := r.updateDescendantPaths(ctx, *f.TenantID, f.Path, newPath); err != nil {
		r.log.Errorf("update descendant paths failed: %s", err.Error())
		// Note: This is a partial failure, the main folder was moved but descendants may have stale paths
	}

	return entity, nil
}

// updateDescendantPaths updates paths of all folders under a path
func (r *FolderRepo) updateDescendantPaths(ctx context.Context, tenantID uint32, oldPathPrefix, newPathPrefix string) error {
	descendants, err := r.entClient.Client().Folder.Query().
		Where(
			folder.TenantIDEQ(tenantID),
			folder.PathHasPrefix(oldPathPrefix+"/"),
		).
		All(ctx)
	if err != nil {
		return err
	}

	for _, d := range descendants {
		newPath := strings.Replace(d.Path, oldPathPrefix, newPathPrefix, 1)
		_, err := r.entClient.Client().Folder.UpdateOneID(d.ID).
			SetPath(newPath).
			SetUpdateTime(time.Now()).
			Save(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete deletes a folder
func (r *FolderRepo) Delete(ctx context.Context, id string, force bool) error {
	// Check if folder has children
	childCount, err := r.entClient.Client().Folder.Query().
		Where(folder.ParentIDEQ(id)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count child folders failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete folder failed")
	}
	if childCount > 0 && !force {
		return wardenV1.ErrorFolderNotEmpty("folder has child folders")
	}

	// Check if folder has active secrets (excluding deleted ones)
	secretCount, err := r.entClient.Client().Secret.Query().
		Where(
			secret.FolderIDEQ(id),
			secret.StatusNEQ(secret.StatusSECRET_STATUS_DELETED),
		).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count secrets failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete folder failed")
	}
	if secretCount > 0 && !force {
		return wardenV1.ErrorFolderNotEmpty("folder contains secrets")
	}

	if force {
		// Delete all descendants recursively
		f, err := r.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if f != nil {
			// Delete all descendant folders
			_, err = r.entClient.Client().Folder.Delete().
				Where(folder.PathHasPrefix(f.Path + "/")).
				Exec(ctx)
			if err != nil {
				r.log.Errorf("delete descendant folders failed: %s", err.Error())
				return wardenV1.ErrorInternalServerError("delete folder failed")
			}
		}
	}

	err = r.entClient.Client().Folder.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return wardenV1.ErrorFolderNotFound("folder not found")
		}
		r.log.Errorf("delete folder failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete folder failed")
	}
	return nil
}

// CountSecrets counts secrets in a folder
func (r *FolderRepo) CountSecrets(ctx context.Context, folderID string) (int, error) {
	count, err := r.entClient.Client().Secret.Query().
		Where(secret.FolderIDEQ(folderID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count secrets failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("count secrets failed")
	}
	return count, nil
}

// CountSubfolders counts subfolders in a folder
func (r *FolderRepo) CountSubfolders(ctx context.Context, folderID string) (int, error) {
	count, err := r.entClient.Client().Folder.Query().
		Where(folder.ParentIDEQ(folderID)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count subfolders failed: %s", err.Error())
		return 0, wardenV1.ErrorInternalServerError("count subfolders failed")
	}
	return count, nil
}

// GetParentID returns the parent folder ID (implements ResourceLookup interface)
func (r *FolderRepo) GetFolderParentID(ctx context.Context, tenantID uint32, folderID string) (*string, error) {
	f, err := r.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}
	return f.ParentID, nil
}

// ToProto converts an ent.Folder to wardenV1.Folder
func (r *FolderRepo) ToProto(entity *ent.Folder) *wardenV1.Folder {
	if entity == nil {
		return nil
	}

	proto := &wardenV1.Folder{
		Id:          entity.ID,
		TenantId:    derefUint32(entity.TenantID),
		Name:        entity.Name,
		Path:        entity.Path,
		Description: entity.Description,
		Depth:       entity.Depth,
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

// ToProtoWithCounts converts an ent.Folder to wardenV1.Folder with counts
func (r *FolderRepo) ToProtoWithCounts(ctx context.Context, entity *ent.Folder) (*wardenV1.Folder, error) {
	proto := r.ToProto(entity)
	if proto == nil {
		return nil, nil
	}

	secretCount, err := r.CountSecrets(ctx, entity.ID)
	if err != nil {
		return nil, err
	}
	proto.SecretCount = int32(secretCount)

	subfolderCount, err := r.CountSubfolders(ctx, entity.ID)
	if err != nil {
		return nil, err
	}
	proto.SubfolderCount = int32(subfolderCount)

	return proto, nil
}

// BuildTree builds a folder tree starting from root folders or a specific folder
func (r *FolderRepo) BuildTree(ctx context.Context, tenantID uint32, rootID *string, maxDepth int32, includeCounts bool) ([]*wardenV1.FolderTreeNode, error) {
	var roots []*ent.Folder
	var err error

	if rootID != nil && *rootID != "" {
		root, err := r.GetByID(ctx, *rootID)
		if err != nil {
			return nil, err
		}
		if root == nil {
			return nil, wardenV1.ErrorFolderNotFound("root folder not found")
		}
		roots = []*ent.Folder{root}
	} else {
		roots, err = r.entClient.Client().Folder.Query().
			Where(
				folder.TenantIDEQ(tenantID),
				folder.ParentIDIsNil(),
			).
			Order(ent.Asc(folder.FieldName)).
			All(ctx)
		if err != nil {
			r.log.Errorf("get root folders failed: %s", err.Error())
			return nil, wardenV1.ErrorInternalServerError("get folder tree failed")
		}
	}

	nodes := make([]*wardenV1.FolderTreeNode, 0, len(roots))
	for _, root := range roots {
		node, err := r.buildTreeNode(ctx, root, 0, maxDepth, includeCounts)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

func (r *FolderRepo) buildTreeNode(ctx context.Context, f *ent.Folder, currentDepth, maxDepth int32, includeCounts bool) (*wardenV1.FolderTreeNode, error) {
	var folderProto *wardenV1.Folder
	var err error

	if includeCounts {
		folderProto, err = r.ToProtoWithCounts(ctx, f)
		if err != nil {
			return nil, err
		}
	} else {
		folderProto = r.ToProto(f)
	}

	node := &wardenV1.FolderTreeNode{
		Folder:   folderProto,
		Children: make([]*wardenV1.FolderTreeNode, 0),
	}

	// Check if we should continue building the tree
	if maxDepth > 0 && currentDepth >= maxDepth {
		return node, nil
	}

	// Get children
	children, err := r.ListByParentID(ctx, *f.TenantID, f.ID)
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

// GetAllDescendantIDs returns all descendant folder IDs
func (r *FolderRepo) GetAllDescendantIDs(ctx context.Context, tenantID uint32, folderID string) ([]string, error) {
	f, err := r.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}

	descendants, err := r.entClient.Client().Folder.Query().
		Where(
			folder.TenantIDEQ(tenantID),
			folder.PathHasPrefix(f.Path+"/"),
		).
		Select(folder.FieldID).
		All(ctx)
	if err != nil {
		r.log.Errorf("get descendant folders failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get descendant folders failed")
	}

	ids := make([]string, 0, len(descendants))
	for _, d := range descendants {
		ids = append(ids, d.ID)
	}

	return ids, nil
}

// Utility function to generate an error message
func folderError(msg string, args ...any) string {
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}

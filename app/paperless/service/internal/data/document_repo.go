package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data/ent/document"

	paperlessV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/paperless/service/v1"
)

type DocumentRepo struct {
	entClient    *entCrud.EntClient[*ent.Client]
	categoryRepo *CategoryRepo
	log          *log.Helper
}

func NewDocumentRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client], categoryRepo *CategoryRepo) *DocumentRepo {
	return &DocumentRepo{
		log:          ctx.NewLoggerHelper("paperless/document/repo"),
		entClient:    entClient,
		categoryRepo: categoryRepo,
	}
}

// Create creates a new document
func (r *DocumentRepo) Create(ctx context.Context, tenantID uint32, categoryID *string, name, description, fileKey, fileName string, fileSize int64, mimeType, checksum string, tags map[string]string, source string, createdBy *uint32) (*ent.Document, error) {
	id := uuid.New().String()

	builder := r.entClient.Client().Document.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetFileKey(fileKey).
		SetFileName(fileName).
		SetFileSize(fileSize).
		SetCreateTime(time.Now())

	if categoryID != nil && *categoryID != "" {
		builder.SetCategoryID(*categoryID)
	}
	if description != "" {
		builder.SetDescription(description)
	}
	if mimeType != "" {
		builder.SetMimeType(mimeType)
	}
	if checksum != "" {
		builder.SetChecksum(checksum)
	}
	if tags != nil {
		builder.SetTags(tags)
	}
	if source != "" {
		builder.SetSource(document.Source(source))
	}
	if createdBy != nil {
		builder.SetCreateBy(*createdBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, paperlessV1.ErrorDocumentAlreadyExists("document already exists")
		}
		r.log.Errorf("create document failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("create document failed")
	}

	return entity, nil
}

// GetByID retrieves a document by ID
func (r *DocumentRepo) GetByID(ctx context.Context, id string) (*ent.Document, error) {
	entity, err := r.entClient.Client().Document.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get document failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("get document failed")
	}
	return entity, nil
}

// GetByFileKey retrieves a document by file key
func (r *DocumentRepo) GetByFileKey(ctx context.Context, fileKey string) (*ent.Document, error) {
	entity, err := r.entClient.Client().Document.Query().
		Where(document.FileKeyEQ(fileKey)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get document by file key failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("get document failed")
	}
	return entity, nil
}

// List lists documents with optional filters
func (r *DocumentRepo) List(ctx context.Context, tenantID uint32, categoryID *string, status *string, nameFilter, mimeTypeFilter *string, includeSubcategories bool, page, pageSize uint32) ([]*ent.Document, int, error) {
	query := r.entClient.Client().Document.Query().
		Where(document.TenantIDEQ(tenantID))

	if categoryID != nil {
		if *categoryID == "" {
			// Root-level documents (no category)
			query = query.Where(document.CategoryIDIsNil())
		} else {
			if includeSubcategories {
				// Get all descendant category IDs
				descendantIDs, err := r.categoryRepo.GetAllDescendantIDs(ctx, tenantID, *categoryID)
				if err != nil {
					return nil, 0, err
				}
				// Include the category itself and all descendants
				allIDs := append([]string{*categoryID}, descendantIDs...)
				query = query.Where(document.CategoryIDIn(allIDs...))
			} else {
				query = query.Where(document.CategoryIDEQ(*categoryID))
			}
		}
	}

	if status != nil && *status != "" {
		query = query.Where(document.StatusEQ(document.Status(*status)))
	}

	if nameFilter != nil && *nameFilter != "" {
		query = query.Where(document.NameContains(*nameFilter))
	}

	if mimeTypeFilter != nil && *mimeTypeFilter != "" {
		query = query.Where(document.MimeTypeContains(*mimeTypeFilter))
	}

	// Count total
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count documents failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("count documents failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		query = query.Offset(offset).Limit(int(pageSize))
	}

	entities, err := query.Order(ent.Desc(document.FieldCreateTime)).All(ctx)
	if err != nil {
		r.log.Errorf("list documents failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("list documents failed")
	}

	return entities, total, nil
}

// Search searches documents
func (r *DocumentRepo) Search(ctx context.Context, tenantID uint32, query string, categoryID *string, includeSubcategories bool, status, mimeTypeFilter *string, tags map[string]string, page, pageSize uint32) ([]*ent.Document, int, error) {
	q := r.entClient.Client().Document.Query().
		Where(
			document.TenantIDEQ(tenantID),
			document.Or(
				document.NameContains(query),
				document.DescriptionContains(query),
				document.FileNameContains(query),
			),
		)

	if categoryID != nil && *categoryID != "" {
		if includeSubcategories {
			descendantIDs, err := r.categoryRepo.GetAllDescendantIDs(ctx, tenantID, *categoryID)
			if err != nil {
				return nil, 0, err
			}
			allIDs := append([]string{*categoryID}, descendantIDs...)
			q = q.Where(document.CategoryIDIn(allIDs...))
		} else {
			q = q.Where(document.CategoryIDEQ(*categoryID))
		}
	}

	if status != nil && *status != "" {
		q = q.Where(document.StatusEQ(document.Status(*status)))
	}

	if mimeTypeFilter != nil && *mimeTypeFilter != "" {
		q = q.Where(document.MimeTypeContains(*mimeTypeFilter))
	}

	// Count total
	total, err := q.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count search results failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("search documents failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		q = q.Offset(offset).Limit(int(pageSize))
	}

	entities, err := q.Order(ent.Desc(document.FieldCreateTime)).All(ctx)
	if err != nil {
		r.log.Errorf("search documents failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("search documents failed")
	}

	return entities, total, nil
}

// Update updates a document
func (r *DocumentRepo) Update(ctx context.Context, id string, name, description *string, status *string, tags map[string]string, updateTags bool, updatedBy *uint32) (*ent.Document, error) {
	builder := r.entClient.Client().Document.UpdateOneID(id).
		SetUpdateTime(time.Now())

	if name != nil {
		builder.SetName(*name)
	}
	if description != nil {
		builder.SetDescription(*description)
	}
	if status != nil {
		builder.SetStatus(document.Status(*status))
	}
	if updateTags {
		builder.SetTags(tags)
	}
	if updatedBy != nil {
		builder.SetUpdateBy(*updatedBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, paperlessV1.ErrorDocumentNotFound("document not found")
		}
		if ent.IsConstraintError(err) {
			return nil, paperlessV1.ErrorDocumentAlreadyExists("document with this name already exists")
		}
		r.log.Errorf("update document failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("update document failed")
	}

	return entity, nil
}

// Move moves a document to a new category
func (r *DocumentRepo) Move(ctx context.Context, id string, newCategoryID *string) (*ent.Document, error) {
	builder := r.entClient.Client().Document.UpdateOneID(id).
		SetUpdateTime(time.Now())

	if newCategoryID != nil && *newCategoryID != "" {
		builder.SetCategoryID(*newCategoryID)
	} else {
		builder.ClearCategoryID()
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, paperlessV1.ErrorDocumentNotFound("document not found")
		}
		if ent.IsConstraintError(err) {
			return nil, paperlessV1.ErrorDocumentAlreadyExists("document with this name already exists in the destination")
		}
		r.log.Errorf("move document failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("move document failed")
	}

	return entity, nil
}

// Delete deletes a document (soft delete by default)
func (r *DocumentRepo) Delete(ctx context.Context, id string, permanent bool) error {
	if permanent {
		err := r.entClient.Client().Document.DeleteOneID(id).Exec(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return paperlessV1.ErrorDocumentNotFound("document not found")
			}
			r.log.Errorf("delete document failed: %s", err.Error())
			return paperlessV1.ErrorInternalServerError("delete document failed")
		}
	} else {
		// Soft delete - set status to DELETED
		_, err := r.entClient.Client().Document.UpdateOneID(id).
			SetStatus(document.StatusDOCUMENT_STATUS_DELETED).
			SetUpdateTime(time.Now()).
			Save(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return paperlessV1.ErrorDocumentNotFound("document not found")
			}
			r.log.Errorf("soft delete document failed: %s", err.Error())
			return paperlessV1.ErrorInternalServerError("delete document failed")
		}
	}
	return nil
}

// BatchDelete deletes multiple documents
func (r *DocumentRepo) BatchDelete(ctx context.Context, ids []string, permanent bool) (int, []string, error) {
	deletedCount := 0
	failedIDs := make([]string, 0)

	for _, id := range ids {
		err := r.Delete(ctx, id, permanent)
		if err != nil {
			failedIDs = append(failedIDs, id)
		} else {
			deletedCount++
		}
	}

	return deletedCount, failedIDs, nil
}

// ToProto converts an ent.Document to paperlessV1.Document
func (r *DocumentRepo) ToProto(entity *ent.Document) *paperlessV1.Document {
	if entity == nil {
		return nil
	}

	proto := &paperlessV1.Document{
		Id:          entity.ID,
		TenantId:    derefUint32(entity.TenantID),
		Name:        entity.Name,
		Description: entity.Description,
		FileKey:     entity.FileKey,
		FileName:    entity.FileName,
		FileSize:    entity.FileSize,
		MimeType:    entity.MimeType,
		Checksum:    entity.Checksum,
		Status:      paperlessV1.DocumentStatus(paperlessV1.DocumentStatus_value[string(entity.Status)]),
		Source:      paperlessV1.DocumentSource(paperlessV1.DocumentSource_value[string(entity.Source)]),
		Tags:        entity.Tags,
	}

	if entity.CategoryID != nil {
		proto.CategoryId = entity.CategoryID
	}
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

// ToProtoWithCategoryPath converts an ent.Document to paperlessV1.Document with category path
func (r *DocumentRepo) ToProtoWithCategoryPath(ctx context.Context, entity *ent.Document) (*paperlessV1.Document, error) {
	proto := r.ToProto(entity)
	if proto == nil {
		return nil, nil
	}

	// Get category path if document has a category
	if entity.CategoryID != nil && *entity.CategoryID != "" {
		cat, err := r.categoryRepo.GetByID(ctx, *entity.CategoryID)
		if err != nil {
			return nil, err
		}
		if cat != nil {
			proto.CategoryPath = cat.Path
		}
	}

	return proto, nil
}

package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data/ent/documentpermission"

	paperlessV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/paperless/service/v1"
)

type PermissionRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewPermissionRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *PermissionRepo {
	return &PermissionRepo{
		log:       ctx.NewLoggerHelper("paperless/permission/repo"),
		entClient: entClient,
	}
}

// Create creates a new permission
func (r *PermissionRepo) Create(ctx context.Context, tenantID uint32, resourceType, resourceID, relation, subjectType, subjectID string, grantedBy *uint32, expiresAt *time.Time) (*ent.DocumentPermission, error) {
	builder := r.entClient.Client().DocumentPermission.Create().
		SetTenantID(tenantID).
		SetResourceType(documentpermission.ResourceType(resourceType)).
		SetResourceID(resourceID).
		SetRelation(documentpermission.Relation(relation)).
		SetSubjectType(documentpermission.SubjectType(subjectType)).
		SetSubjectID(subjectID).
		SetCreateTime(time.Now())

	if grantedBy != nil {
		builder.SetGrantedBy(*grantedBy)
	}
	if expiresAt != nil {
		builder.SetExpiresAt(*expiresAt)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, paperlessV1.ErrorPermissionAlreadyExists("permission already exists")
		}
		r.log.Errorf("create permission failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("create permission failed")
	}

	return entity, nil
}

// GetByTuple retrieves a permission by its tuple
func (r *PermissionRepo) GetByTuple(ctx context.Context, tenantID uint32, resourceType, resourceID, relation, subjectType, subjectID string) (*ent.DocumentPermission, error) {
	entity, err := r.entClient.Client().DocumentPermission.Query().
		Where(
			documentpermission.TenantIDEQ(tenantID),
			documentpermission.ResourceTypeEQ(documentpermission.ResourceType(resourceType)),
			documentpermission.ResourceIDEQ(resourceID),
			documentpermission.RelationEQ(documentpermission.Relation(relation)),
			documentpermission.SubjectTypeEQ(documentpermission.SubjectType(subjectType)),
			documentpermission.SubjectIDEQ(subjectID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get permission failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("get permission failed")
	}
	return entity, nil
}

// List lists permissions with optional filters
func (r *PermissionRepo) List(ctx context.Context, tenantID uint32, resourceType, resourceID, subjectType, subjectID *string, page, pageSize uint32) ([]*ent.DocumentPermission, int, error) {
	query := r.entClient.Client().DocumentPermission.Query().
		Where(documentpermission.TenantIDEQ(tenantID))

	if resourceType != nil && *resourceType != "" {
		query = query.Where(documentpermission.ResourceTypeEQ(documentpermission.ResourceType(*resourceType)))
	}
	if resourceID != nil && *resourceID != "" {
		query = query.Where(documentpermission.ResourceIDEQ(*resourceID))
	}
	if subjectType != nil && *subjectType != "" {
		query = query.Where(documentpermission.SubjectTypeEQ(documentpermission.SubjectType(*subjectType)))
	}
	if subjectID != nil && *subjectID != "" {
		query = query.Where(documentpermission.SubjectIDEQ(*subjectID))
	}

	// Count total
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count permissions failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("count permissions failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		query = query.Offset(offset).Limit(int(pageSize))
	}

	entities, err := query.Order(ent.Desc(documentpermission.FieldCreateTime)).All(ctx)
	if err != nil {
		r.log.Errorf("list permissions failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("list permissions failed")
	}

	return entities, total, nil
}

// ListByResource lists permissions for a specific resource
func (r *PermissionRepo) ListByResource(ctx context.Context, tenantID uint32, resourceType, resourceID string) ([]*ent.DocumentPermission, error) {
	entities, err := r.entClient.Client().DocumentPermission.Query().
		Where(
			documentpermission.TenantIDEQ(tenantID),
			documentpermission.ResourceTypeEQ(documentpermission.ResourceType(resourceType)),
			documentpermission.ResourceIDEQ(resourceID),
		).
		All(ctx)
	if err != nil {
		r.log.Errorf("list permissions by resource failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("list permissions failed")
	}
	return entities, nil
}

// ListBySubject lists permissions for a specific subject
func (r *PermissionRepo) ListBySubject(ctx context.Context, tenantID uint32, subjectType, subjectID string) ([]*ent.DocumentPermission, error) {
	entities, err := r.entClient.Client().DocumentPermission.Query().
		Where(
			documentpermission.TenantIDEQ(tenantID),
			documentpermission.SubjectTypeEQ(documentpermission.SubjectType(subjectType)),
			documentpermission.SubjectIDEQ(subjectID),
		).
		All(ctx)
	if err != nil {
		r.log.Errorf("list permissions by subject failed: %s", err.Error())
		return nil, paperlessV1.ErrorInternalServerError("list permissions failed")
	}
	return entities, nil
}

// Delete deletes a permission by tuple
func (r *PermissionRepo) Delete(ctx context.Context, tenantID uint32, resourceType, resourceID string, relation *string, subjectType, subjectID string) error {
	query := r.entClient.Client().DocumentPermission.Delete().
		Where(
			documentpermission.TenantIDEQ(tenantID),
			documentpermission.ResourceTypeEQ(documentpermission.ResourceType(resourceType)),
			documentpermission.ResourceIDEQ(resourceID),
			documentpermission.SubjectTypeEQ(documentpermission.SubjectType(subjectType)),
			documentpermission.SubjectIDEQ(subjectID),
		)

	if relation != nil && *relation != "" {
		query = query.Where(documentpermission.RelationEQ(documentpermission.Relation(*relation)))
	}

	_, err := query.Exec(ctx)
	if err != nil {
		r.log.Errorf("delete permission failed: %s", err.Error())
		return paperlessV1.ErrorInternalServerError("delete permission failed")
	}
	return nil
}

// DeleteByResource deletes all permissions for a resource
func (r *PermissionRepo) DeleteByResource(ctx context.Context, tenantID uint32, resourceType, resourceID string) error {
	_, err := r.entClient.Client().DocumentPermission.Delete().
		Where(
			documentpermission.TenantIDEQ(tenantID),
			documentpermission.ResourceTypeEQ(documentpermission.ResourceType(resourceType)),
			documentpermission.ResourceIDEQ(resourceID),
		).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete permissions by resource failed: %s", err.Error())
		return paperlessV1.ErrorInternalServerError("delete permissions failed")
	}
	return nil
}

// HasPermission checks if a subject has a specific relation on a resource
func (r *PermissionRepo) HasPermission(ctx context.Context, tenantID uint32, resourceType, resourceID, relation, subjectType, subjectID string) (bool, error) {
	count, err := r.entClient.Client().DocumentPermission.Query().
		Where(
			documentpermission.TenantIDEQ(tenantID),
			documentpermission.ResourceTypeEQ(documentpermission.ResourceType(resourceType)),
			documentpermission.ResourceIDEQ(resourceID),
			documentpermission.RelationEQ(documentpermission.Relation(relation)),
			documentpermission.SubjectTypeEQ(documentpermission.SubjectType(subjectType)),
			documentpermission.SubjectIDEQ(subjectID),
			documentpermission.Or(
				documentpermission.ExpiresAtIsNil(),
				documentpermission.ExpiresAtGT(time.Now()),
			),
		).
		Count(ctx)
	if err != nil {
		r.log.Errorf("check permission failed: %s", err.Error())
		return false, paperlessV1.ErrorInternalServerError("check permission failed")
	}
	return count > 0, nil
}

// GetHighestRelation returns the highest relation a subject has on a resource
func (r *PermissionRepo) GetHighestRelation(ctx context.Context, tenantID uint32, resourceType, resourceID, subjectType, subjectID string) (string, error) {
	entities, err := r.entClient.Client().DocumentPermission.Query().
		Where(
			documentpermission.TenantIDEQ(tenantID),
			documentpermission.ResourceTypeEQ(documentpermission.ResourceType(resourceType)),
			documentpermission.ResourceIDEQ(resourceID),
			documentpermission.SubjectTypeEQ(documentpermission.SubjectType(subjectType)),
			documentpermission.SubjectIDEQ(subjectID),
			documentpermission.Or(
				documentpermission.ExpiresAtIsNil(),
				documentpermission.ExpiresAtGT(time.Now()),
			),
		).
		All(ctx)
	if err != nil {
		r.log.Errorf("get highest relation failed: %s", err.Error())
		return "", paperlessV1.ErrorInternalServerError("get highest relation failed")
	}

	if len(entities) == 0 {
		return "", nil
	}

	// Relation hierarchy: OWNER > EDITOR > SHARER > VIEWER
	hierarchy := map[string]int{
		"RELATION_OWNER":  4,
		"RELATION_EDITOR": 3,
		"RELATION_SHARER": 2,
		"RELATION_VIEWER": 1,
	}

	highest := ""
	highestRank := 0
	for _, e := range entities {
		rank := hierarchy[string(e.Relation)]
		if rank > highestRank {
			highestRank = rank
			highest = string(e.Relation)
		}
	}

	return highest, nil
}

// ListAccessibleResources lists resources accessible by a subject
func (r *PermissionRepo) ListAccessibleResources(ctx context.Context, tenantID uint32, subjectType, subjectID, resourceType string, page, pageSize uint32) ([]string, int, error) {
	query := r.entClient.Client().DocumentPermission.Query().
		Where(
			documentpermission.TenantIDEQ(tenantID),
			documentpermission.SubjectTypeEQ(documentpermission.SubjectType(subjectType)),
			documentpermission.SubjectIDEQ(subjectID),
			documentpermission.ResourceTypeEQ(documentpermission.ResourceType(resourceType)),
			documentpermission.Or(
				documentpermission.ExpiresAtIsNil(),
				documentpermission.ExpiresAtGT(time.Now()),
			),
		)

	// Get unique resource IDs
	// Note: This is a simplified implementation. For production, consider using DISTINCT
	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list accessible resources failed: %s", err.Error())
		return nil, 0, paperlessV1.ErrorInternalServerError("list accessible resources failed")
	}

	// Deduplicate resource IDs
	resourceIDSet := make(map[string]struct{})
	for _, e := range entities {
		resourceIDSet[e.ResourceID] = struct{}{}
	}

	resourceIDs := make([]string, 0, len(resourceIDSet))
	for id := range resourceIDSet {
		resourceIDs = append(resourceIDs, id)
	}

	total := len(resourceIDs)

	// Apply pagination
	if page > 0 && pageSize > 0 {
		start := int((page - 1) * pageSize)
		end := start + int(pageSize)
		if start >= len(resourceIDs) {
			resourceIDs = []string{}
		} else if end > len(resourceIDs) {
			resourceIDs = resourceIDs[start:]
		} else {
			resourceIDs = resourceIDs[start:end]
		}
	}

	return resourceIDs, total, nil
}

// ToProto converts an ent.DocumentPermission to paperlessV1.PermissionTuple
func (r *PermissionRepo) ToProto(entity *ent.DocumentPermission) *paperlessV1.PermissionTuple {
	if entity == nil {
		return nil
	}

	proto := &paperlessV1.PermissionTuple{
		Id:           uint32(entity.ID),
		TenantId:     derefUint32(entity.TenantID),
		ResourceType: paperlessV1.ResourceType(paperlessV1.ResourceType_value[string(entity.ResourceType)]),
		ResourceId:   entity.ResourceID,
		Relation:     paperlessV1.Relation(paperlessV1.Relation_value[string(entity.Relation)]),
		SubjectType:  paperlessV1.SubjectType(paperlessV1.SubjectType_value[string(entity.SubjectType)]),
		SubjectId:    entity.SubjectID,
	}

	if entity.GrantedBy != nil {
		proto.GrantedBy = entity.GrantedBy
	}
	if entity.ExpiresAt != nil && !entity.ExpiresAt.IsZero() {
		proto.ExpiresAt = timestamppb.New(*entity.ExpiresAt)
	}
	if entity.CreateTime != nil && !entity.CreateTime.IsZero() {
		proto.CreateTime = timestamppb.New(*entity.CreateTime)
	}

	return proto
}

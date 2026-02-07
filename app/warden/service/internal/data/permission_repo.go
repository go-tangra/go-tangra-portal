package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/authz"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent/permission"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
)

type PermissionRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewPermissionRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *PermissionRepo {
	return &PermissionRepo{
		log:       ctx.NewLoggerHelper("permission/repo"),
		entClient: entClient,
	}
}

// Create creates a new permission
func (r *PermissionRepo) Create(ctx context.Context, tenantID uint32, resourceType, resourceID string, relation string, subjectType, subjectID string, grantedBy *uint32, expiresAt *time.Time) (*ent.Permission, error) {
	builder := r.entClient.Client().Permission.Create().
		SetTenantID(tenantID).
		SetResourceType(permission.ResourceType(resourceType)).
		SetResourceID(resourceID).
		SetRelation(permission.Relation(relation)).
		SetSubjectType(permission.SubjectType(subjectType)).
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
			return nil, wardenV1.ErrorPermissionAlreadyExists("permission already exists")
		}
		r.log.Errorf("create permission failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("create permission failed")
	}

	return entity, nil
}

// GetDirectPermissions returns permissions directly on a resource
func (r *PermissionRepo) GetDirectPermissions(ctx context.Context, tenantID uint32, resourceType authz.ResourceType, resourceID string) ([]authz.PermissionTuple, error) {
	entities, err := r.entClient.Client().Permission.Query().
		Where(
			permission.TenantIDEQ(tenantID),
			permission.ResourceTypeEQ(permission.ResourceType(resourceType)),
			permission.ResourceIDEQ(resourceID),
		).
		All(ctx)
	if err != nil {
		r.log.Errorf("get direct permissions failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get permissions failed")
	}

	tuples := make([]authz.PermissionTuple, 0, len(entities))
	for _, e := range entities {
		tuples = append(tuples, r.toAuthzTuple(e))
	}

	return tuples, nil
}

// GetSubjectPermissions returns all permissions for a subject
func (r *PermissionRepo) GetSubjectPermissions(ctx context.Context, tenantID uint32, subjectType authz.SubjectType, subjectID string) ([]authz.PermissionTuple, error) {
	entities, err := r.entClient.Client().Permission.Query().
		Where(
			permission.TenantIDEQ(tenantID),
			permission.SubjectTypeEQ(permission.SubjectType(subjectType)),
			permission.SubjectIDEQ(subjectID),
		).
		All(ctx)
	if err != nil {
		r.log.Errorf("get subject permissions failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get permissions failed")
	}

	tuples := make([]authz.PermissionTuple, 0, len(entities))
	for _, e := range entities {
		tuples = append(tuples, r.toAuthzTuple(e))
	}

	return tuples, nil
}

// HasPermission checks if a specific permission exists
func (r *PermissionRepo) HasPermission(ctx context.Context, tenantID uint32, resourceType authz.ResourceType, resourceID string, subjectType authz.SubjectType, subjectID string) (*authz.PermissionTuple, error) {
	entity, err := r.entClient.Client().Permission.Query().
		Where(
			permission.TenantIDEQ(tenantID),
			permission.ResourceTypeEQ(permission.ResourceType(resourceType)),
			permission.ResourceIDEQ(resourceID),
			permission.SubjectTypeEQ(permission.SubjectType(subjectType)),
			permission.SubjectIDEQ(subjectID),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("check permission failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("check permission failed")
	}

	tuple := r.toAuthzTuple(entity)
	return &tuple, nil
}

// CreatePermission creates a new permission (implements PermissionStore interface)
func (r *PermissionRepo) CreatePermission(ctx context.Context, tuple authz.PermissionTuple) (*authz.PermissionTuple, error) {
	entity, err := r.Create(ctx, tuple.TenantID, string(tuple.ResourceType), tuple.ResourceID, string(tuple.Relation), string(tuple.SubjectType), tuple.SubjectID, tuple.GrantedBy, tuple.ExpiresAt)
	if err != nil {
		return nil, err
	}

	result := r.toAuthzTuple(entity)
	return &result, nil
}

// DeletePermission deletes a permission
func (r *PermissionRepo) DeletePermission(ctx context.Context, tenantID uint32, resourceType authz.ResourceType, resourceID string, relation *authz.Relation, subjectType authz.SubjectType, subjectID string) error {
	query := r.entClient.Client().Permission.Delete().
		Where(
			permission.TenantIDEQ(tenantID),
			permission.ResourceTypeEQ(permission.ResourceType(resourceType)),
			permission.ResourceIDEQ(resourceID),
			permission.SubjectTypeEQ(permission.SubjectType(subjectType)),
			permission.SubjectIDEQ(subjectID),
		)

	if relation != nil {
		query = query.Where(permission.RelationEQ(permission.Relation(*relation)))
	}

	_, err := query.Exec(ctx)
	if err != nil {
		r.log.Errorf("delete permission failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete permission failed")
	}

	return nil
}

// ListResourcesBySubject lists resources accessible by a subject
func (r *PermissionRepo) ListResourcesBySubject(ctx context.Context, tenantID uint32, subjectType authz.SubjectType, subjectID string, resourceType authz.ResourceType) ([]string, error) {
	entities, err := r.entClient.Client().Permission.Query().
		Where(
			permission.TenantIDEQ(tenantID),
			permission.SubjectTypeEQ(permission.SubjectType(subjectType)),
			permission.SubjectIDEQ(subjectID),
			permission.ResourceTypeEQ(permission.ResourceType(resourceType)),
		).
		Select(permission.FieldResourceID).
		All(ctx)
	if err != nil {
		r.log.Errorf("list resources by subject failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("list resources failed")
	}

	ids := make([]string, 0, len(entities))
	for _, e := range entities {
		ids = append(ids, e.ResourceID)
	}

	return ids, nil
}

// List lists permissions with optional filters
func (r *PermissionRepo) List(ctx context.Context, tenantID uint32, resourceType *string, resourceID *string, subjectType *string, subjectID *string, page, pageSize uint32) ([]*ent.Permission, int, error) {
	query := r.entClient.Client().Permission.Query().
		Where(permission.TenantIDEQ(tenantID))

	if resourceType != nil && *resourceType != "" {
		query = query.Where(permission.ResourceTypeEQ(permission.ResourceType(*resourceType)))
	}
	if resourceID != nil && *resourceID != "" {
		query = query.Where(permission.ResourceIDEQ(*resourceID))
	}
	if subjectType != nil && *subjectType != "" {
		query = query.Where(permission.SubjectTypeEQ(permission.SubjectType(*subjectType)))
	}
	if subjectID != nil && *subjectID != "" {
		query = query.Where(permission.SubjectIDEQ(*subjectID))
	}

	// Count total
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count permissions failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("count permissions failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		query = query.Offset(offset).Limit(int(pageSize))
	}

	entities, err := query.
		Order(ent.Desc(permission.FieldCreateTime)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list permissions failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("list permissions failed")
	}

	return entities, total, nil
}

// DeleteByResource deletes all permissions for a resource
func (r *PermissionRepo) DeleteByResource(ctx context.Context, tenantID uint32, resourceType, resourceID string) error {
	_, err := r.entClient.Client().Permission.Delete().
		Where(
			permission.TenantIDEQ(tenantID),
			permission.ResourceTypeEQ(permission.ResourceType(resourceType)),
			permission.ResourceIDEQ(resourceID),
		).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete permissions by resource failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete permissions failed")
	}
	return nil
}

// toAuthzTuple converts an ent.Permission to authz.PermissionTuple
func (r *PermissionRepo) toAuthzTuple(entity *ent.Permission) authz.PermissionTuple {
	tuple := authz.PermissionTuple{
		ID:           uint32(entity.ID),
		TenantID:     derefUint32(entity.TenantID),
		ResourceType: authz.ResourceType(entity.ResourceType),
		ResourceID:   entity.ResourceID,
		Relation:     authz.Relation(entity.Relation),
		SubjectType:  authz.SubjectType(entity.SubjectType),
		SubjectID:    entity.SubjectID,
		GrantedBy:    entity.GrantedBy,
		ExpiresAt:    entity.ExpiresAt,
	}
	if entity.CreateTime != nil {
		tuple.CreateTime = *entity.CreateTime
	}
	return tuple
}

// ToProto converts an ent.Permission to wardenV1.PermissionTuple
func (r *PermissionRepo) ToProto(entity *ent.Permission) *wardenV1.PermissionTuple {
	if entity == nil {
		return nil
	}

	proto := &wardenV1.PermissionTuple{
		Id:         uint32(entity.ID),
		TenantId:   derefUint32(entity.TenantID),
		ResourceId: entity.ResourceID,
		SubjectId:  entity.SubjectID,
	}

	// Map resource type
	switch entity.ResourceType {
	case permission.ResourceTypeRESOURCE_TYPE_FOLDER:
		proto.ResourceType = wardenV1.ResourceType_RESOURCE_TYPE_FOLDER
	case permission.ResourceTypeRESOURCE_TYPE_SECRET:
		proto.ResourceType = wardenV1.ResourceType_RESOURCE_TYPE_SECRET
	default:
		proto.ResourceType = wardenV1.ResourceType_RESOURCE_TYPE_UNSPECIFIED
	}

	// Map relation
	switch entity.Relation {
	case permission.RelationRELATION_OWNER:
		proto.Relation = wardenV1.Relation_RELATION_OWNER
	case permission.RelationRELATION_EDITOR:
		proto.Relation = wardenV1.Relation_RELATION_EDITOR
	case permission.RelationRELATION_VIEWER:
		proto.Relation = wardenV1.Relation_RELATION_VIEWER
	case permission.RelationRELATION_SHARER:
		proto.Relation = wardenV1.Relation_RELATION_SHARER
	default:
		proto.Relation = wardenV1.Relation_RELATION_UNSPECIFIED
	}

	// Map subject type
	switch entity.SubjectType {
	case permission.SubjectTypeSUBJECT_TYPE_USER:
		proto.SubjectType = wardenV1.SubjectType_SUBJECT_TYPE_USER
	case permission.SubjectTypeSUBJECT_TYPE_ROLE:
		proto.SubjectType = wardenV1.SubjectType_SUBJECT_TYPE_ROLE
	case permission.SubjectTypeSUBJECT_TYPE_TENANT:
		proto.SubjectType = wardenV1.SubjectType_SUBJECT_TYPE_TENANT
	default:
		proto.SubjectType = wardenV1.SubjectType_SUBJECT_TYPE_UNSPECIFIED
	}

	if entity.GrantedBy != nil {
		proto.GrantedBy = entity.GrantedBy
	}
	if entity.ExpiresAt != nil {
		proto.ExpiresAt = timestamppb.New(*entity.ExpiresAt)
	}
	if entity.CreateTime != nil && !entity.CreateTime.IsZero() {
		proto.CreateTime = timestamppb.New(*entity.CreateTime)
	}

	return proto
}

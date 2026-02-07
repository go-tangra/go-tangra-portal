package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data"

	paperlessV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/paperless/service/v1"
)

type PermissionService struct {
	paperlessV1.UnimplementedPaperlessPermissionServiceServer

	log      *log.Helper
	permRepo *data.PermissionRepo
}

func NewPermissionService(
	ctx *bootstrap.Context,
	permRepo *data.PermissionRepo,
) *PermissionService {
	return &PermissionService{
		log:      ctx.NewLoggerHelper("paperless/service/permission"),
		permRepo: permRepo,
	}
}

// GrantAccess grants access to a resource
func (s *PermissionService) GrantAccess(ctx context.Context, req *paperlessV1.GrantAccessRequest) (*paperlessV1.GrantAccessResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	grantedBy := getUserIDAsUint32(ctx)

	var expiresAt *interface{}
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		expiresAt = new(interface{})
		*expiresAt = t
	}

	var expTime *interface{}
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		expTime = new(interface{})
		_ = t
		_ = expTime
	}

	// Convert expiration time
	var expiresAtTime *interface{}
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		_ = t
		expiresAtTime = nil
	}
	_ = expiresAtTime
	_ = expiresAt

	permission, err := s.permRepo.Create(ctx, tenantID,
		req.ResourceType.String(),
		req.ResourceId,
		req.Relation.String(),
		req.SubjectType.String(),
		req.SubjectId,
		grantedBy,
		nil, // expiresAt - simplified for now
	)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.GrantAccessResponse{
		Permission: s.permRepo.ToProto(permission),
	}, nil
}

// RevokeAccess revokes access from a resource
func (s *PermissionService) RevokeAccess(ctx context.Context, req *paperlessV1.RevokeAccessRequest) (*emptypb.Empty, error) {
	tenantID := getTenantIDFromContext(ctx)

	var relation *string
	if req.Relation != nil && *req.Relation != paperlessV1.Relation_RELATION_UNSPECIFIED {
		r := req.Relation.String()
		relation = &r
	}

	err := s.permRepo.Delete(ctx, tenantID,
		req.ResourceType.String(),
		req.ResourceId,
		relation,
		req.SubjectType.String(),
		req.SubjectId,
	)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListPermissions lists permissions
func (s *PermissionService) ListPermissions(ctx context.Context, req *paperlessV1.ListPermissionsRequest) (*paperlessV1.ListPermissionsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	var resourceType, subjectType *string
	if req.ResourceType != nil && *req.ResourceType != paperlessV1.ResourceType_RESOURCE_TYPE_UNSPECIFIED {
		rt := req.ResourceType.String()
		resourceType = &rt
	}
	if req.SubjectType != nil && *req.SubjectType != paperlessV1.SubjectType_SUBJECT_TYPE_UNSPECIFIED {
		st := req.SubjectType.String()
		subjectType = &st
	}

	permissions, total, err := s.permRepo.List(ctx, tenantID, resourceType, req.ResourceId, subjectType, req.SubjectId, page, pageSize)
	if err != nil {
		return nil, err
	}

	protoPermissions := make([]*paperlessV1.PermissionTuple, 0, len(permissions))
	for _, perm := range permissions {
		protoPermissions = append(protoPermissions, s.permRepo.ToProto(perm))
	}

	return &paperlessV1.ListPermissionsResponse{
		Permissions: protoPermissions,
		Total:       uint32(total),
	}, nil
}

// CheckAccess checks if a subject has access to a resource
func (s *PermissionService) CheckAccess(ctx context.Context, req *paperlessV1.CheckAccessRequest) (*paperlessV1.CheckAccessResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	// Get permission to relation mapping
	permissionRelations := getPermissionRelations(req.Permission)

	// Check if user has any of the required relations
	allowed := false
	for _, relation := range permissionRelations {
		has, err := s.permRepo.HasPermission(ctx, tenantID,
			req.ResourceType.String(),
			req.ResourceId,
			relation,
			"SUBJECT_TYPE_USER",
			req.UserId,
		)
		if err != nil {
			return nil, err
		}
		if has {
			allowed = true
			break
		}
	}

	var reason *string
	if !allowed {
		r := "user does not have the required permission"
		reason = &r
	}

	return &paperlessV1.CheckAccessResponse{
		Allowed: allowed,
		Reason:  reason,
	}, nil
}

// ListAccessibleResources lists resources accessible by a subject
func (s *PermissionService) ListAccessibleResources(ctx context.Context, req *paperlessV1.ListAccessibleResourcesRequest) (*paperlessV1.ListAccessibleResourcesResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	resourceIDs, total, err := s.permRepo.ListAccessibleResources(ctx, tenantID,
		"SUBJECT_TYPE_USER",
		req.UserId,
		req.ResourceType.String(),
		page, pageSize,
	)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.ListAccessibleResourcesResponse{
		ResourceIds: resourceIDs,
		Total:       uint32(total),
	}, nil
}

// GetEffectivePermissions gets effective permissions for a subject on a resource
func (s *PermissionService) GetEffectivePermissions(ctx context.Context, req *paperlessV1.GetEffectivePermissionsRequest) (*paperlessV1.GetEffectivePermissionsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	highestRelation, err := s.permRepo.GetHighestRelation(ctx, tenantID,
		req.ResourceType.String(),
		req.ResourceId,
		"SUBJECT_TYPE_USER",
		req.UserId,
	)
	if err != nil {
		return nil, err
	}

	// Get all permissions based on highest relation
	permissions := getRelationPermissions(highestRelation)

	return &paperlessV1.GetEffectivePermissionsResponse{
		Permissions:     permissions,
		HighestRelation: paperlessV1.Relation(paperlessV1.Relation_value[highestRelation]),
	}, nil
}

// getPermissionRelations returns the relations that grant a permission
func getPermissionRelations(permission paperlessV1.Permission) []string {
	switch permission {
	case paperlessV1.Permission_PERMISSION_READ, paperlessV1.Permission_PERMISSION_DOWNLOAD:
		return []string{"RELATION_OWNER", "RELATION_EDITOR", "RELATION_VIEWER", "RELATION_SHARER"}
	case paperlessV1.Permission_PERMISSION_WRITE:
		return []string{"RELATION_OWNER", "RELATION_EDITOR"}
	case paperlessV1.Permission_PERMISSION_DELETE:
		return []string{"RELATION_OWNER", "RELATION_EDITOR"}
	case paperlessV1.Permission_PERMISSION_SHARE:
		return []string{"RELATION_OWNER", "RELATION_SHARER"}
	default:
		return []string{}
	}
}

// getRelationPermissions returns the permissions granted by a relation
func getRelationPermissions(relation string) []paperlessV1.Permission {
	switch relation {
	case "RELATION_OWNER":
		return []paperlessV1.Permission{
			paperlessV1.Permission_PERMISSION_READ,
			paperlessV1.Permission_PERMISSION_WRITE,
			paperlessV1.Permission_PERMISSION_DELETE,
			paperlessV1.Permission_PERMISSION_SHARE,
			paperlessV1.Permission_PERMISSION_DOWNLOAD,
		}
	case "RELATION_EDITOR":
		return []paperlessV1.Permission{
			paperlessV1.Permission_PERMISSION_READ,
			paperlessV1.Permission_PERMISSION_WRITE,
			paperlessV1.Permission_PERMISSION_DELETE,
			paperlessV1.Permission_PERMISSION_DOWNLOAD,
		}
	case "RELATION_VIEWER":
		return []paperlessV1.Permission{
			paperlessV1.Permission_PERMISSION_READ,
			paperlessV1.Permission_PERMISSION_DOWNLOAD,
		}
	case "RELATION_SHARER":
		return []paperlessV1.Permission{
			paperlessV1.Permission_PERMISSION_READ,
			paperlessV1.Permission_PERMISSION_SHARE,
			paperlessV1.Permission_PERMISSION_DOWNLOAD,
		}
	default:
		return []paperlessV1.Permission{}
	}
}

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

type PermissionService struct {
	wardenV1.UnimplementedWardenPermissionServiceServer

	log        *log.Helper
	permRepo   *data.PermissionRepo
	folderRepo *data.FolderRepo
	secretRepo *data.SecretRepo
	engine     *authz.Engine
	checker    *authz.Checker
}

func NewPermissionService(
	ctx *bootstrap.Context,
	permRepo *data.PermissionRepo,
	folderRepo *data.FolderRepo,
	secretRepo *data.SecretRepo,
	engine *authz.Engine,
	checker *authz.Checker,
) *PermissionService {
	return &PermissionService{
		log:        ctx.NewLoggerHelper("warden/service/permission"),
		permRepo:   permRepo,
		folderRepo: folderRepo,
		secretRepo: secretRepo,
		engine:     engine,
		checker:    checker,
	}
}

// GrantAccess grants access to a resource
func (s *PermissionService) GrantAccess(ctx context.Context, req *wardenV1.GrantAccessRequest) (*wardenV1.GrantAccessResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check if user has share permission on the resource
	resourceType := mapProtoResourceTypeToAuthz(req.ResourceType)
	if err := s.checker.RequirePermission(ctx, tenantID, userID, resourceType, req.ResourceId, authz.PermissionShare); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to share this resource")
	}

	// Verify the resource exists
	if req.ResourceType == wardenV1.ResourceType_RESOURCE_TYPE_FOLDER {
		folder, err := s.folderRepo.GetByID(ctx, req.ResourceId)
		if err != nil {
			return nil, err
		}
		if folder == nil {
			return nil, wardenV1.ErrorFolderNotFound("folder not found")
		}
	} else if req.ResourceType == wardenV1.ResourceType_RESOURCE_TYPE_SECRET {
		secret, err := s.secretRepo.GetByID(ctx, req.ResourceId)
		if err != nil {
			return nil, err
		}
		if secret == nil {
			return nil, wardenV1.ErrorSecretNotFound("secret not found")
		}
	}

	grantedBy := getUserIDAsUint32(ctx)
	var expiresAt *int64
	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime().Unix()
		expiresAt = &t
	}

	var expiresAtTime *int64
	_ = expiresAtTime
	_ = expiresAt

	permission, err := s.permRepo.Create(
		ctx,
		tenantID,
		string(mapProtoResourceTypeToAuthz(req.ResourceType)),
		req.ResourceId,
		string(mapProtoRelationToAuthz(req.Relation)),
		string(mapProtoSubjectTypeToAuthz(req.SubjectType)),
		req.SubjectId,
		grantedBy,
		nil, // TODO: Convert expiresAt
	)
	if err != nil {
		return nil, err
	}

	return &wardenV1.GrantAccessResponse{
		Permission: s.permRepo.ToProto(permission),
	}, nil
}

// RevokeAccess revokes access from a resource
func (s *PermissionService) RevokeAccess(ctx context.Context, req *wardenV1.RevokeAccessRequest) (*emptypb.Empty, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// Check if user has share permission on the resource
	resourceType := mapProtoResourceTypeToAuthz(req.ResourceType)
	if err := s.checker.RequirePermission(ctx, tenantID, userID, resourceType, req.ResourceId, authz.PermissionShare); err != nil {
		return nil, wardenV1.ErrorAccessDenied("no permission to manage access on this resource")
	}

	var relation *authz.Relation
	if req.Relation != nil && *req.Relation != wardenV1.Relation_RELATION_UNSPECIFIED {
		r := mapProtoRelationToAuthz(*req.Relation)
		relation = &r
	}

	err := s.permRepo.DeletePermission(
		ctx,
		tenantID,
		mapProtoResourceTypeToAuthz(req.ResourceType),
		req.ResourceId,
		relation,
		mapProtoSubjectTypeToAuthz(req.SubjectType),
		req.SubjectId,
	)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListPermissions lists permissions on a resource
func (s *PermissionService) ListPermissions(ctx context.Context, req *wardenV1.ListPermissionsRequest) (*wardenV1.ListPermissionsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	userID := getUserIDFromContext(ctx)

	// If resource is specified, check permission
	if req.ResourceId != nil && *req.ResourceId != "" && req.ResourceType != nil {
		resourceType := mapProtoResourceTypeToAuthz(*req.ResourceType)
		if err := s.checker.RequirePermission(ctx, tenantID, userID, resourceType, *req.ResourceId, authz.PermissionRead); err != nil {
			return nil, wardenV1.ErrorAccessDenied("no permission to view permissions on this resource")
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

	var resourceType, subjectType *string
	if req.ResourceType != nil && *req.ResourceType != wardenV1.ResourceType_RESOURCE_TYPE_UNSPECIFIED {
		rt := string(mapProtoResourceTypeToAuthz(*req.ResourceType))
		resourceType = &rt
	}
	if req.SubjectType != nil && *req.SubjectType != wardenV1.SubjectType_SUBJECT_TYPE_UNSPECIFIED {
		st := string(mapProtoSubjectTypeToAuthz(*req.SubjectType))
		subjectType = &st
	}

	permissions, total, err := s.permRepo.List(ctx, tenantID, resourceType, req.ResourceId, subjectType, req.SubjectId, page, pageSize)
	if err != nil {
		return nil, err
	}

	protoPermissions := make([]*wardenV1.PermissionTuple, 0, len(permissions))
	for _, p := range permissions {
		protoPermissions = append(protoPermissions, s.permRepo.ToProto(p))
	}

	return &wardenV1.ListPermissionsResponse{
		Permissions: protoPermissions,
		Total:       uint32(total),
	}, nil
}

// CheckAccess checks if a subject has access to a resource
func (s *PermissionService) CheckAccess(ctx context.Context, req *wardenV1.CheckAccessRequest) (*wardenV1.CheckAccessResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	allowed, reason := s.checker.CheckPermission(
		ctx,
		tenantID,
		req.UserId,
		mapProtoResourceTypeToAuthz(req.ResourceType),
		req.ResourceId,
		mapProtoPermissionToAuthz(req.Permission),
	)

	return &wardenV1.CheckAccessResponse{
		Allowed: allowed,
		Reason:  &reason,
	}, nil
}

// ListAccessibleResources lists resources accessible by a subject
func (s *PermissionService) ListAccessibleResources(ctx context.Context, req *wardenV1.ListAccessibleResourcesRequest) (*wardenV1.ListAccessibleResourcesResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(100)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	resourceIDs, err := s.engine.ListAccessibleResources(
		ctx,
		tenantID,
		req.UserId,
		mapProtoResourceTypeToAuthz(req.ResourceType),
		mapProtoPermissionToAuthz(req.Permission),
	)
	if err != nil {
		return nil, err
	}

	// Apply pagination
	total := uint32(len(resourceIDs))
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > uint32(len(resourceIDs)) {
		start = uint32(len(resourceIDs))
	}
	if end > uint32(len(resourceIDs)) {
		end = uint32(len(resourceIDs))
	}
	resourceIDs = resourceIDs[start:end]

	return &wardenV1.ListAccessibleResourcesResponse{
		ResourceIds: resourceIDs,
		Total:       total,
	}, nil
}

// GetEffectivePermissions gets effective permissions for a subject on a resource
func (s *PermissionService) GetEffectivePermissions(ctx context.Context, req *wardenV1.GetEffectivePermissionsRequest) (*wardenV1.GetEffectivePermissionsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	permissions, highestRelation := s.checker.GetEffectivePermissions(
		ctx,
		tenantID,
		req.UserId,
		mapProtoResourceTypeToAuthz(req.ResourceType),
		req.ResourceId,
	)

	protoPermissions := make([]wardenV1.Permission, 0, len(permissions))
	for _, p := range permissions {
		protoPermissions = append(protoPermissions, mapAuthzPermissionToProto(p))
	}

	return &wardenV1.GetEffectivePermissionsResponse{
		Permissions:     protoPermissions,
		HighestRelation: mapAuthzRelationToProto(highestRelation),
	}, nil
}

// Helper functions for type mapping

func mapProtoResourceTypeToAuthz(rt wardenV1.ResourceType) authz.ResourceType {
	switch rt {
	case wardenV1.ResourceType_RESOURCE_TYPE_FOLDER:
		return authz.ResourceTypeFolder
	case wardenV1.ResourceType_RESOURCE_TYPE_SECRET:
		return authz.ResourceTypeSecret
	default:
		return authz.ResourceType("")
	}
}

func mapProtoRelationToAuthz(r wardenV1.Relation) authz.Relation {
	switch r {
	case wardenV1.Relation_RELATION_OWNER:
		return authz.RelationOwner
	case wardenV1.Relation_RELATION_EDITOR:
		return authz.RelationEditor
	case wardenV1.Relation_RELATION_VIEWER:
		return authz.RelationViewer
	case wardenV1.Relation_RELATION_SHARER:
		return authz.RelationSharer
	default:
		return authz.Relation("")
	}
}

func mapProtoSubjectTypeToAuthz(st wardenV1.SubjectType) authz.SubjectType {
	switch st {
	case wardenV1.SubjectType_SUBJECT_TYPE_USER:
		return authz.SubjectTypeUser
	case wardenV1.SubjectType_SUBJECT_TYPE_ROLE:
		return authz.SubjectTypeRole
	case wardenV1.SubjectType_SUBJECT_TYPE_TENANT:
		return authz.SubjectTypeTenant
	default:
		return authz.SubjectType("")
	}
}

func mapProtoPermissionToAuthz(p wardenV1.Permission) authz.Permission {
	switch p {
	case wardenV1.Permission_PERMISSION_READ:
		return authz.PermissionRead
	case wardenV1.Permission_PERMISSION_WRITE:
		return authz.PermissionWrite
	case wardenV1.Permission_PERMISSION_DELETE:
		return authz.PermissionDelete
	case wardenV1.Permission_PERMISSION_SHARE:
		return authz.PermissionShare
	default:
		return authz.Permission("")
	}
}

func mapAuthzPermissionToProto(p authz.Permission) wardenV1.Permission {
	switch p {
	case authz.PermissionRead:
		return wardenV1.Permission_PERMISSION_READ
	case authz.PermissionWrite:
		return wardenV1.Permission_PERMISSION_WRITE
	case authz.PermissionDelete:
		return wardenV1.Permission_PERMISSION_DELETE
	case authz.PermissionShare:
		return wardenV1.Permission_PERMISSION_SHARE
	default:
		return wardenV1.Permission_PERMISSION_UNSPECIFIED
	}
}

func mapAuthzRelationToProto(r authz.Relation) wardenV1.Relation {
	switch r {
	case authz.RelationOwner:
		return wardenV1.Relation_RELATION_OWNER
	case authz.RelationEditor:
		return wardenV1.Relation_RELATION_EDITOR
	case authz.RelationViewer:
		return wardenV1.Relation_RELATION_VIEWER
	case authz.RelationSharer:
		return wardenV1.Relation_RELATION_SHARER
	default:
		return wardenV1.Relation_RELATION_UNSPECIFIED
	}
}

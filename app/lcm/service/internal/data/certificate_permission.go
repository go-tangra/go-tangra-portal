package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/certificatepermission"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/lcmclient"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

// CertificatePermissionRepo handles certificate permission data operations
type CertificatePermissionRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewCertificatePermissionRepo creates a new CertificatePermissionRepo
func NewCertificatePermissionRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *CertificatePermissionRepo {
	return &CertificatePermissionRepo{
		log:       ctx.NewLoggerHelper("certificate-permission/repo"),
		entClient: entClient,
	}
}

// Create creates a new certificate permission grant
func (r *CertificatePermissionRepo) Create(
	ctx context.Context,
	tenantID uint32,
	certificateID string,
	granteeID uint32,
	permType certificatepermission.PermissionType,
	grantedBy string,
	expiresAt *time.Time,
) (*ent.CertificatePermission, error) {
	builder := r.entClient.Client().CertificatePermission.Create().
		SetTenantID(tenantID).
		SetCertificateID(certificateID).
		SetGranteeID(granteeID).
		SetPermissionType(permType).
		SetGrantedBy(grantedBy)

	if expiresAt != nil {
		builder.SetExpiresAt(*expiresAt)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		// Check for unique constraint violation (duplicate grant)
		if ent.IsConstraintError(err) {
			return nil, lcmV1.ErrorConflict("permission already exists for this certificate and grantee")
		}
		r.log.Errorf("create certificate permission failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create certificate permission failed")
	}
	return entity, nil
}

// Delete removes a certificate permission grant
func (r *CertificatePermissionRepo) Delete(ctx context.Context, certificateID string, granteeID uint32) error {
	_, err := r.entClient.Client().CertificatePermission.Delete().
		Where(
			certificatepermission.CertificateIDEQ(certificateID),
			certificatepermission.GranteeIDEQ(granteeID),
		).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete certificate permission failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("delete certificate permission failed")
	}
	return nil
}

// DeleteByID removes a certificate permission by ID
func (r *CertificatePermissionRepo) DeleteByID(ctx context.Context, id uint32) error {
	err := r.entClient.Client().CertificatePermission.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return lcmV1.ErrorNotFound("certificate permission not found")
		}
		r.log.Errorf("delete certificate permission failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("delete certificate permission failed")
	}
	return nil
}

// GetByCertificateAndGrantee retrieves a specific permission grant
func (r *CertificatePermissionRepo) GetByCertificateAndGrantee(ctx context.Context, certificateID string, granteeID uint32) (*ent.CertificatePermission, error) {
	entity, err := r.entClient.Client().CertificatePermission.Query().
		Where(
			certificatepermission.CertificateIDEQ(certificateID),
			certificatepermission.GranteeIDEQ(granteeID),
		).
		WithGrantee().
		WithIssuedCertificate().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("query certificate permission failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate permission failed")
	}
	return entity, nil
}

// ListByCertificate lists all permissions granted for a specific certificate
func (r *CertificatePermissionRepo) ListByCertificate(ctx context.Context, certificateID string) ([]*ent.CertificatePermission, error) {
	entities, err := r.entClient.Client().CertificatePermission.Query().
		Where(certificatepermission.CertificateIDEQ(certificateID)).
		WithGrantee().
		Order(ent.Desc(certificatepermission.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list certificate permissions by certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list certificate permissions failed")
	}
	return entities, nil
}

// ListByGrantee lists all permissions granted to a specific client
func (r *CertificatePermissionRepo) ListByGrantee(ctx context.Context, granteeID uint32) ([]*ent.CertificatePermission, error) {
	entities, err := r.entClient.Client().CertificatePermission.Query().
		Where(certificatepermission.GranteeIDEQ(granteeID)).
		WithIssuedCertificate(func(q *ent.IssuedCertificateQuery) {
			q.WithLcmClient()
		}).
		Order(ent.Desc(certificatepermission.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list certificate permissions by grantee failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list certificate permissions failed")
	}
	return entities, nil
}

// ListByGranteeClientID lists all permissions granted to a client by client_id string
func (r *CertificatePermissionRepo) ListByGranteeClientID(ctx context.Context, tenantID uint32, clientID string) ([]*ent.CertificatePermission, error) {
	entities, err := r.entClient.Client().CertificatePermission.Query().
		Where(
			certificatepermission.TenantIDEQ(tenantID),
			certificatepermission.HasGranteeWith(lcmclient.ClientIDEQ(clientID)),
		).
		WithIssuedCertificate(func(q *ent.IssuedCertificateQuery) {
			q.WithLcmClient()
		}).
		WithGrantee().
		Order(ent.Desc(certificatepermission.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list certificate permissions by grantee client ID failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list certificate permissions failed")
	}
	return entities, nil
}

// ListByTenant lists all permissions in a tenant with optional filters
func (r *CertificatePermissionRepo) ListByTenant(
	ctx context.Context,
	tenantID uint32,
	certificateID *string,
	granteeClientID *string,
	grantedBy *string,
	permType *certificatepermission.PermissionType,
	includeExpired bool,
	page, pageSize uint32,
) ([]*ent.CertificatePermission, int, error) {
	query := r.entClient.Client().CertificatePermission.Query().
		Where(certificatepermission.TenantIDEQ(tenantID))

	if certificateID != nil && *certificateID != "" {
		query = query.Where(certificatepermission.CertificateIDEQ(*certificateID))
	}
	if grantedBy != nil && *grantedBy != "" {
		query = query.Where(certificatepermission.GrantedByEQ(*grantedBy))
	}
	if permType != nil {
		query = query.Where(certificatepermission.PermissionTypeEQ(*permType))
	}
	if granteeClientID != nil && *granteeClientID != "" {
		query = query.Where(certificatepermission.HasGranteeWith(lcmclient.ClientIDEQ(*granteeClientID)))
	}
	if !includeExpired {
		query = query.Where(
			certificatepermission.Or(
				certificatepermission.ExpiresAtIsNil(),
				certificatepermission.ExpiresAtGT(time.Now()),
			),
		)
	}

	// Get total count first
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count certificate permissions failed: %s", err.Error())
		return nil, 0, lcmV1.ErrorInternalServerError("count certificate permissions failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		query = query.Offset(int((page - 1) * pageSize)).Limit(int(pageSize))
	}

	entities, err := query.
		WithGrantee().
		WithIssuedCertificate(func(q *ent.IssuedCertificateQuery) {
			q.WithLcmClient()
		}).
		Order(ent.Desc(certificatepermission.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list certificate permissions failed: %s", err.Error())
		return nil, 0, lcmV1.ErrorInternalServerError("list certificate permissions failed")
	}

	return entities, total, nil
}

// HasPermission checks if a grantee has at least the required permission level for a certificate
// Returns true if the grantee has a valid (non-expired) permission >= required level
func (r *CertificatePermissionRepo) HasPermission(
	ctx context.Context,
	certificateID string,
	granteeID uint32,
	requiredType certificatepermission.PermissionType,
) (bool, *ent.CertificatePermission, error) {
	entity, err := r.entClient.Client().CertificatePermission.Query().
		Where(
			certificatepermission.CertificateIDEQ(certificateID),
			certificatepermission.GranteeIDEQ(granteeID),
			certificatepermission.Or(
				certificatepermission.ExpiresAtIsNil(),
				certificatepermission.ExpiresAtGT(time.Now()),
			),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return false, nil, nil
		}
		r.log.Errorf("check certificate permission failed: %s", err.Error())
		return false, nil, lcmV1.ErrorInternalServerError("check certificate permission failed")
	}

	// Check if the granted permission level is sufficient
	grantedLevel := permissionLevel(entity.PermissionType)
	requiredLevel := permissionLevel(requiredType)

	return grantedLevel >= requiredLevel, entity, nil
}

// HasPermissionByClientID checks permission by client_id string
func (r *CertificatePermissionRepo) HasPermissionByClientID(
	ctx context.Context,
	certificateID string,
	tenantID uint32,
	clientID string,
	requiredType certificatepermission.PermissionType,
) (bool, *ent.CertificatePermission, error) {
	entity, err := r.entClient.Client().CertificatePermission.Query().
		Where(
			certificatepermission.CertificateIDEQ(certificateID),
			certificatepermission.TenantIDEQ(tenantID),
			certificatepermission.HasGranteeWith(lcmclient.ClientIDEQ(clientID)),
			certificatepermission.Or(
				certificatepermission.ExpiresAtIsNil(),
				certificatepermission.ExpiresAtGT(time.Now()),
			),
		).
		WithGrantee().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return false, nil, nil
		}
		r.log.Errorf("check certificate permission by client ID failed: %s", err.Error())
		return false, nil, lcmV1.ErrorInternalServerError("check certificate permission failed")
	}

	grantedLevel := permissionLevel(entity.PermissionType)
	requiredLevel := permissionLevel(requiredType)
	if grantedLevel >= requiredLevel {
		return true, entity, nil
	}

	return false, nil, nil
}

// permissionLevel returns a numeric level for permission type comparison
// Higher level means more access
func permissionLevel(pt certificatepermission.PermissionType) int {
	switch pt {
	case certificatepermission.PermissionTypeREAD:
		return 1
	case certificatepermission.PermissionTypeDOWNLOAD:
		return 2
	case certificatepermission.PermissionTypeFULL:
		return 3
	default:
		return 0
	}
}

// ToProto converts an ent.CertificatePermission to lcmV1.CertificatePermission
func (r *CertificatePermissionRepo) ToProto(entity *ent.CertificatePermission) *lcmV1.CertificatePermission {
	if entity == nil {
		return nil
	}

	proto := &lcmV1.CertificatePermission{
		Id:              entity.ID,
		CertificateId:   entity.CertificateID,
		GranteeClientId: entity.GranteeID,
		PermissionType:  entPermissionTypeToProto(entity.PermissionType),
		GrantedBy:       entity.GrantedBy,
	}

	if entity.ExpiresAt != nil {
		proto.ExpiresAt = timestamppb.New(*entity.ExpiresAt)
	}

	proto.CreatedAt = timestamppb.New(entity.CreatedAt)
	if !entity.UpdatedAt.IsZero() {
		proto.UpdatedAt = timestamppb.New(entity.UpdatedAt)
	}

	// Add grantee client name if edge is loaded
	if entity.Edges.Grantee != nil {
		proto.GranteeClientName = entity.Edges.Grantee.ClientID
	}

	return proto
}

// ProtoPermissionTypeToEnt converts proto permission type to ent
func ProtoPermissionTypeToEnt(pt lcmV1.PermissionType) certificatepermission.PermissionType {
	switch pt {
	case lcmV1.PermissionType_PERMISSION_TYPE_READ:
		return certificatepermission.PermissionTypeREAD
	case lcmV1.PermissionType_PERMISSION_TYPE_DOWNLOAD:
		return certificatepermission.PermissionTypeDOWNLOAD
	case lcmV1.PermissionType_PERMISSION_TYPE_FULL:
		return certificatepermission.PermissionTypeFULL
	default:
		return certificatepermission.PermissionTypeREAD
	}
}

// entPermissionTypeToProto converts ent permission type to proto
func entPermissionTypeToProto(pt certificatepermission.PermissionType) lcmV1.PermissionType {
	switch pt {
	case certificatepermission.PermissionTypeREAD:
		return lcmV1.PermissionType_PERMISSION_TYPE_READ
	case certificatepermission.PermissionTypeDOWNLOAD:
		return lcmV1.PermissionType_PERMISSION_TYPE_DOWNLOAD
	case certificatepermission.PermissionTypeFULL:
		return lcmV1.PermissionType_PERMISSION_TYPE_FULL
	default:
		return lcmV1.PermissionType_PERMISSION_TYPE_UNSPECIFIED
	}
}

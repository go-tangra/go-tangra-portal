package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/tenantsecret"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

type TenantSecretRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewTenantSecretRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *TenantSecretRepo {
	return &TenantSecretRepo{
		log:       ctx.NewLoggerHelper("tenant_secret/repo"),
		entClient: entClient,
	}
}

// HashSecret hashes a secret using SHA-256
func HashSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

// GetBySecretHash retrieves a tenant secret by its hashed secret value
func (r *TenantSecretRepo) GetBySecretHash(ctx context.Context, secretHash string) (*ent.TenantSecret, error) {
	entity, err := r.entClient.Client().TenantSecret.Query().
		Where(
			tenantsecret.SecretHashEQ(secretHash),
			tenantsecret.StatusEQ(tenantsecret.StatusTENANT_SECRET_STATUS_ACTIVE),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil // Not found is not an error
		}
		r.log.Errorf("query tenant secret failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query tenant secret failed")
	}

	// Check if expired
	if entity.ExpiresAt != nil && entity.ExpiresAt.Before(time.Now()) {
		return nil, nil // Expired secret is treated as not found
	}

	return entity, nil
}

// GetTenantIDBySecret looks up a tenant ID from a raw secret
func (r *TenantSecretRepo) GetTenantIDBySecret(ctx context.Context, secret string) (uint32, error) {
	secretHash := HashSecret(secret)
	entity, err := r.GetBySecretHash(ctx, secretHash)
	if err != nil {
		return 0, err
	}
	if entity == nil {
		return 0, nil // Not found
	}
	return entity.TenantID, nil
}

// Create creates a new tenant secret
func (r *TenantSecretRepo) Create(ctx context.Context, tenantID uint32, secret string, description string) (*ent.TenantSecret, error) {
	secretHash := HashSecret(secret)

	builder := r.entClient.Client().TenantSecret.Create().
		SetTenantID(tenantID).
		SetSecretHash(secretHash).
		SetStatus(tenantsecret.StatusTENANT_SECRET_STATUS_ACTIVE).
		SetCreateTime(time.Now())

	if description != "" {
		builder.SetDescription(description)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create tenant secret failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create tenant secret failed")
	}

	return entity, nil
}

// CreateWithExpiry creates a new tenant secret with an expiration time
func (r *TenantSecretRepo) CreateWithExpiry(ctx context.Context, tenantID uint32, secret string, description string, expiresAt *time.Time) (*ent.TenantSecret, error) {
	secretHash := HashSecret(secret)

	builder := r.entClient.Client().TenantSecret.Create().
		SetTenantID(tenantID).
		SetSecretHash(secretHash).
		SetStatus(tenantsecret.StatusTENANT_SECRET_STATUS_ACTIVE).
		SetCreateTime(time.Now())

	if description != "" {
		builder.SetDescription(description)
	}
	if expiresAt != nil {
		builder.SetExpiresAt(*expiresAt)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create tenant secret failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create tenant secret failed")
	}

	return entity, nil
}

// ListByTenantID lists all secrets for a tenant
func (r *TenantSecretRepo) ListByTenantID(ctx context.Context, tenantID uint32) ([]*ent.TenantSecret, error) {
	entities, err := r.entClient.Client().TenantSecret.Query().
		Where(tenantsecret.TenantIDEQ(tenantID)).
		Order(ent.Desc(tenantsecret.FieldCreateTime)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list tenant secrets failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list tenant secrets failed")
	}
	return entities, nil
}

// ListAll lists all tenant secrets
func (r *TenantSecretRepo) ListAll(ctx context.Context) ([]*ent.TenantSecret, error) {
	entities, err := r.entClient.Client().TenantSecret.Query().
		Order(ent.Desc(tenantsecret.FieldCreateTime)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list all tenant secrets failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list all tenant secrets failed")
	}
	return entities, nil
}

// GetByID retrieves a tenant secret by ID
func (r *TenantSecretRepo) GetByID(ctx context.Context, id uint32) (*ent.TenantSecret, error) {
	entity, err := r.entClient.Client().TenantSecret.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get tenant secret failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("get tenant secret failed")
	}
	return entity, nil
}

// UpdateStatus updates the status of a tenant secret
func (r *TenantSecretRepo) UpdateStatus(ctx context.Context, id uint32, status tenantsecret.Status) (*ent.TenantSecret, error) {
	entity, err := r.entClient.Client().TenantSecret.UpdateOneID(id).
		SetStatus(status).
		SetUpdateTime(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("update tenant secret status failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("update tenant secret status failed")
	}
	return entity, nil
}

// Delete deletes a tenant secret
func (r *TenantSecretRepo) Delete(ctx context.Context, id uint32) error {
	err := r.entClient.Client().TenantSecret.DeleteOneID(id).Exec(ctx)
	if err != nil {
		r.log.Errorf("delete tenant secret failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("delete tenant secret failed")
	}
	return nil
}

// Rotate creates a new secret and optionally disables the old one
func (r *TenantSecretRepo) Rotate(ctx context.Context, oldID uint32, newSecret string, disableOld bool) (*ent.TenantSecret, *ent.TenantSecret, error) {
	// Get the old secret
	oldEntity, err := r.GetByID(ctx, oldID)
	if err != nil {
		return nil, nil, err
	}
	if oldEntity == nil {
		return nil, nil, lcmV1.ErrorNotFound("tenant secret not found")
	}

	// Create new secret
	newEntity, err := r.Create(ctx, oldEntity.TenantID, newSecret, oldEntity.Description)
	if err != nil {
		return nil, nil, err
	}

	// Optionally disable old secret
	if disableOld {
		oldEntity, err = r.UpdateStatus(ctx, oldID, tenantsecret.StatusTENANT_SECRET_STATUS_DISABLED)
		if err != nil {
			return newEntity, nil, err
		}
	}

	return newEntity, oldEntity, nil
}

// ToProto converts an ent.TenantSecret to lcmV1.TenantSecret
func (r *TenantSecretRepo) ToProto(entity *ent.TenantSecret) *lcmV1.TenantSecret {
	if entity == nil {
		return nil
	}

	proto := &lcmV1.TenantSecret{
		Id:       &entity.ID,
		TenantId: &entity.TenantID,
	}

	if entity.Description != "" {
		proto.Description = &entity.Description
	}

	// Map status
	switch entity.Status {
	case tenantsecret.StatusTENANT_SECRET_STATUS_ACTIVE:
		s := lcmV1.TenantSecretStatus_TENANT_SECRET_STATUS_ACTIVE
		proto.Status = &s
	case tenantsecret.StatusTENANT_SECRET_STATUS_DISABLED:
		s := lcmV1.TenantSecretStatus_TENANT_SECRET_STATUS_DISABLED
		proto.Status = &s
	default:
		s := lcmV1.TenantSecretStatus_TENANT_SECRET_STATUS_UNSPECIFIED
		proto.Status = &s
	}

	return proto
}

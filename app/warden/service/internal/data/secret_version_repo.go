package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data/ent/secretversion"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
)

type SecretVersionRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewSecretVersionRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *SecretVersionRepo {
	return &SecretVersionRepo{
		log:       ctx.NewLoggerHelper("secret_version/repo"),
		entClient: entClient,
	}
}

// Create creates a new secret version
func (r *SecretVersionRepo) Create(ctx context.Context, secretID string, versionNumber int32, vaultPath, comment, checksum string, createdBy *uint32) (*ent.SecretVersion, error) {
	builder := r.entClient.Client().SecretVersion.Create().
		SetSecretID(secretID).
		SetVersionNumber(versionNumber).
		SetVaultPath(vaultPath).
		SetChecksum(checksum).
		SetCreateTime(time.Now())

	if comment != "" {
		builder.SetComment(comment)
	}
	if createdBy != nil {
		builder.SetCreateBy(*createdBy)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, wardenV1.ErrorConflict("version already exists")
		}
		r.log.Errorf("create secret version failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("create secret version failed")
	}

	return entity, nil
}

// GetBySecretAndVersion retrieves a version by secret ID and version number
func (r *SecretVersionRepo) GetBySecretAndVersion(ctx context.Context, secretID string, versionNumber int32) (*ent.SecretVersion, error) {
	entity, err := r.entClient.Client().SecretVersion.Query().
		Where(
			secretversion.SecretIDEQ(secretID),
			secretversion.VersionNumberEQ(versionNumber),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get secret version failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get secret version failed")
	}
	return entity, nil
}

// GetLatestVersion retrieves the latest version for a secret
func (r *SecretVersionRepo) GetLatestVersion(ctx context.Context, secretID string) (*ent.SecretVersion, error) {
	entity, err := r.entClient.Client().SecretVersion.Query().
		Where(secretversion.SecretIDEQ(secretID)).
		Order(ent.Desc(secretversion.FieldVersionNumber)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get latest secret version failed: %s", err.Error())
		return nil, wardenV1.ErrorInternalServerError("get secret version failed")
	}
	return entity, nil
}

// List lists all versions for a secret
func (r *SecretVersionRepo) List(ctx context.Context, secretID string, page, pageSize uint32) ([]*ent.SecretVersion, int, error) {
	query := r.entClient.Client().SecretVersion.Query().
		Where(secretversion.SecretIDEQ(secretID))

	// Count total
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count secret versions failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("count secret versions failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		offset := int((page - 1) * pageSize)
		query = query.Offset(offset).Limit(int(pageSize))
	}

	entities, err := query.
		Order(ent.Desc(secretversion.FieldVersionNumber)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list secret versions failed: %s", err.Error())
		return nil, 0, wardenV1.ErrorInternalServerError("list secret versions failed")
	}

	return entities, total, nil
}

// GetNextVersionNumber returns the next version number for a secret
func (r *SecretVersionRepo) GetNextVersionNumber(ctx context.Context, secretID string) (int32, error) {
	latest, err := r.GetLatestVersion(ctx, secretID)
	if err != nil {
		return 0, err
	}
	if latest == nil {
		return 1, nil
	}
	return latest.VersionNumber + 1, nil
}

// DeleteBySecretID deletes all versions for a secret
func (r *SecretVersionRepo) DeleteBySecretID(ctx context.Context, secretID string) error {
	_, err := r.entClient.Client().SecretVersion.Delete().
		Where(secretversion.SecretIDEQ(secretID)).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete secret versions failed: %s", err.Error())
		return wardenV1.ErrorInternalServerError("delete secret versions failed")
	}
	return nil
}

// ToProto converts an ent.SecretVersion to wardenV1.SecretVersion
func (r *SecretVersionRepo) ToProto(entity *ent.SecretVersion) *wardenV1.SecretVersion {
	if entity == nil {
		return nil
	}

	proto := &wardenV1.SecretVersion{
		Id:            uint32(entity.ID),
		SecretId:      entity.SecretID,
		VersionNumber: entity.VersionNumber,
		Comment:       entity.Comment,
		Checksum:      entity.Checksum,
	}

	if entity.CreateBy != nil {
		proto.CreatedBy = entity.CreateBy
	}
	if entity.CreateTime != nil && !entity.CreateTime.IsZero() {
		proto.CreateTime = timestamppb.New(*entity.CreateTime)
	}

	return proto
}

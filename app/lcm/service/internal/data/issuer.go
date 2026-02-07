package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/acmeissuer"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/issuer"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/selfsignedissuer"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

type IssuerRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewIssuerRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *IssuerRepo {
	return &IssuerRepo{
		log:       ctx.NewLoggerHelper("issuer/repo"),
		entClient: entClient,
	}
}

// GetByTenantAndName retrieves an issuer by tenant_id and name
func (r *IssuerRepo) GetByTenantAndName(ctx context.Context, tenantID uint32, name string) (*ent.Issuer, error) {
	entity, err := r.entClient.Client().Issuer.Query().
		Where(
			issuer.TenantIDEQ(tenantID),
			issuer.NameEQ(name),
		).
		WithSelfSignedConfigs().
		WithAcmeConfigs().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("query issuer failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query issuer failed")
	}
	return entity, nil
}

// GetByID retrieves an issuer by ID
func (r *IssuerRepo) GetByID(ctx context.Context, id uint32) (*ent.Issuer, error) {
	entity, err := r.entClient.Client().Issuer.Query().
		Where(issuer.IDEQ(id)).
		WithSelfSignedConfigs().
		WithAcmeConfigs().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("query issuer failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query issuer failed")
	}
	return entity, nil
}

// ListByTenant retrieves all issuers for a tenant
func (r *IssuerRepo) ListByTenant(ctx context.Context, tenantID uint32) ([]*ent.Issuer, error) {
	entities, err := r.entClient.Client().Issuer.Query().
		Where(issuer.TenantIDEQ(tenantID)).
		WithSelfSignedConfigs().
		WithAcmeConfigs().
		All(ctx)
	if err != nil {
		r.log.Errorf("list issuers failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list issuers failed")
	}
	return entities, nil
}

// Create creates a new issuer with its type-specific configuration
func (r *IssuerRepo) Create(ctx context.Context, tenantID uint32, req *lcmV1.CreateIssuerRequest) (*ent.Issuer, error) {
	// Start a transaction
	tx, err := r.entClient.Client().Tx(ctx)
	if err != nil {
		r.log.Errorf("failed to start transaction: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("failed to create issuer")
	}

	// Create the base issuer
	issuerType := issuer.Type(req.GetType())
	builder := tx.Issuer.Create().
		SetTenantID(tenantID).
		SetName(req.GetName()).
		SetType(issuerType).
		SetDescription(req.GetDescription()).
		SetCreateTime(time.Now())

	// Map status
	if req.Status != lcmV1.IssuerStatus_ISSUER_STATUS_UNSPECIFIED {
		status := mapProtoStatusToEnt(req.Status)
		builder.SetStatus(status)
	}

	newIssuer, err := builder.Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		if ent.IsConstraintError(err) {
			return nil, lcmV1.ErrorConflict("issuer with name '%s' already exists for this tenant", req.GetName())
		}
		r.log.Errorf("create issuer failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create issuer failed")
	}

	// Create type-specific configuration
	switch req.GetType() {
	case "self-signed":
		if req.SelfIssuer != nil {
			_, err = tx.SelfSignedIssuer.Create().
				SetIssuerID(newIssuer.ID).
				SetCommonName(req.SelfIssuer.GetCommonName()).
				SetDNSNames(req.SelfIssuer.GetDnsNames()).
				SetIPAddresses(req.SelfIssuer.GetIpAddresses()).
				SetCaCommonName(req.SelfIssuer.GetCaCommonName()).
				SetCaOrganization(req.SelfIssuer.GetCaOrganization()).
				SetCaOrganizationalUnit(req.SelfIssuer.GetCaOrganizationalUnit()).
				SetCaCountry(req.SelfIssuer.GetCaCountry()).
				SetCaProvince(req.SelfIssuer.GetCaProvince()).
				SetCaLocality(req.SelfIssuer.GetCaLocality()).
				SetCaValidityDays(req.SelfIssuer.GetCaValidityDays()).
				Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				r.log.Errorf("create self-signed issuer config failed: %s", err.Error())
				return nil, lcmV1.ErrorInternalServerError("create issuer configuration failed")
			}
		}
	case "acme":
		if req.AcmeIssuer != nil {
			builder := tx.AcmeIssuer.Create().
				SetIssuerID(newIssuer.ID).
				SetEmail(req.AcmeIssuer.GetEmail()).
				SetEndpoint(req.AcmeIssuer.GetEndpoint()).
				SetKeyType(acmeissuer.KeyType(req.AcmeIssuer.GetKeyType())).
				SetKeySize(req.AcmeIssuer.GetKeySize()).
				SetMaxRetries(req.AcmeIssuer.GetMaxRetries()).
				SetBaseDelay(req.AcmeIssuer.GetBaseDelay()).
				SetChallengeType(acmeissuer.ChallengeType(req.AcmeIssuer.GetChallengeType().String()))

			if req.AcmeIssuer.GetProviderName() != "" {
				builder.SetProviderName(req.AcmeIssuer.GetProviderName())
			}
			if len(req.AcmeIssuer.GetProviderConfig()) > 0 {
				builder.SetProviderConfig(req.AcmeIssuer.GetProviderConfig())
			}
			// EAB (External Account Binding) support
			if req.AcmeIssuer.EabKid != nil && *req.AcmeIssuer.EabKid != "" {
				builder.SetEabKid(*req.AcmeIssuer.EabKid)
			}
			if req.AcmeIssuer.EabHmacKey != nil && *req.AcmeIssuer.EabHmacKey != "" {
				builder.SetEabHmacKey(*req.AcmeIssuer.EabHmacKey)
			}

			_, err = builder.Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				r.log.Errorf("create acme issuer config failed: %s", err.Error())
				return nil, lcmV1.ErrorInternalServerError("create issuer configuration failed")
			}
		}
	}

	if err := tx.Commit(); err != nil {
		r.log.Errorf("commit transaction failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create issuer failed")
	}

	// Fetch the complete issuer with edges
	return r.GetByID(ctx, newIssuer.ID)
}

// Update updates an existing issuer
func (r *IssuerRepo) Update(ctx context.Context, id uint32, tenantID uint32, req *lcmV1.UpdateIssuerRequest) (*ent.Issuer, error) {
	// Verify the issuer belongs to the tenant
	existingIssuer, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existingIssuer == nil {
		return nil, lcmV1.ErrorNotFound("issuer not found")
	}
	// Check tenant ownership (TenantID is *uint32)
	var existingTenantID uint32
	if existingIssuer.TenantID != nil {
		existingTenantID = *existingIssuer.TenantID
	}
	if existingTenantID != tenantID {
		return nil, lcmV1.ErrorForbidden("issuer does not belong to this tenant")
	}

	tx, err := r.entClient.Client().Tx(ctx)
	if err != nil {
		r.log.Errorf("failed to start transaction: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("failed to update issuer")
	}

	// Update the base issuer
	builder := tx.Issuer.UpdateOneID(id).
		SetUpdateTime(time.Now())

	if req.GetDescription() != "" {
		builder.SetDescription(req.GetDescription())
	}
	if req.Status != lcmV1.IssuerStatus_ISSUER_STATUS_UNSPECIFIED {
		builder.SetStatus(mapProtoStatusToEnt(req.Status))
	}

	_, err = builder.Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		r.log.Errorf("update issuer failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("update issuer failed")
	}

	// Update type-specific configuration
	switch existingIssuer.Type {
	case issuer.TypeSelfSigned:
		if req.SelfIssuer != nil && len(existingIssuer.Edges.SelfSignedConfigs) > 0 {
			configID := existingIssuer.Edges.SelfSignedConfigs[0].ID
			updateBuilder := tx.SelfSignedIssuer.UpdateOneID(configID)

			if req.SelfIssuer.GetCommonName() != "" {
				updateBuilder.SetCommonName(req.SelfIssuer.GetCommonName())
			}
			if len(req.SelfIssuer.GetDnsNames()) > 0 {
				updateBuilder.SetDNSNames(req.SelfIssuer.GetDnsNames())
			}
			if len(req.SelfIssuer.GetIpAddresses()) > 0 {
				updateBuilder.SetIPAddresses(req.SelfIssuer.GetIpAddresses())
			}
			if req.SelfIssuer.GetCaCommonName() != "" {
				updateBuilder.SetCaCommonName(req.SelfIssuer.GetCaCommonName())
			}
			if req.SelfIssuer.GetCaOrganization() != "" {
				updateBuilder.SetCaOrganization(req.SelfIssuer.GetCaOrganization())
			}
			if req.SelfIssuer.GetCaOrganizationalUnit() != "" {
				updateBuilder.SetCaOrganizationalUnit(req.SelfIssuer.GetCaOrganizationalUnit())
			}
			if req.SelfIssuer.GetCaCountry() != "" {
				updateBuilder.SetCaCountry(req.SelfIssuer.GetCaCountry())
			}
			if req.SelfIssuer.GetCaProvince() != "" {
				updateBuilder.SetCaProvince(req.SelfIssuer.GetCaProvince())
			}
			if req.SelfIssuer.GetCaLocality() != "" {
				updateBuilder.SetCaLocality(req.SelfIssuer.GetCaLocality())
			}
			if req.SelfIssuer.GetCaValidityDays() > 0 {
				updateBuilder.SetCaValidityDays(req.SelfIssuer.GetCaValidityDays())
			}

			_, err = updateBuilder.Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				r.log.Errorf("update self-signed issuer config failed: %s", err.Error())
				return nil, lcmV1.ErrorInternalServerError("update issuer configuration failed")
			}
		}
	case issuer.TypeAcme:
		if req.AcmeIssuer != nil && len(existingIssuer.Edges.AcmeConfigs) > 0 {
			configID := existingIssuer.Edges.AcmeConfigs[0].ID
			updateBuilder := tx.AcmeIssuer.UpdateOneID(configID)

			if req.AcmeIssuer.GetEmail() != "" {
				updateBuilder.SetEmail(req.AcmeIssuer.GetEmail())
			}
			if req.AcmeIssuer.GetEndpoint() != "" {
				updateBuilder.SetEndpoint(req.AcmeIssuer.GetEndpoint())
			}
			if req.AcmeIssuer.GetKeyType() != "" {
				updateBuilder.SetKeyType(acmeissuer.KeyType(req.AcmeIssuer.GetKeyType()))
			}
			if req.AcmeIssuer.GetKeySize() > 0 {
				updateBuilder.SetKeySize(req.AcmeIssuer.GetKeySize())
			}
			if req.AcmeIssuer.GetMaxRetries() > 0 {
				updateBuilder.SetMaxRetries(req.AcmeIssuer.GetMaxRetries())
			}
			if req.AcmeIssuer.GetBaseDelay() != "" {
				updateBuilder.SetBaseDelay(req.AcmeIssuer.GetBaseDelay())
			}
			if req.AcmeIssuer.GetProviderName() != "" {
				updateBuilder.SetProviderName(req.AcmeIssuer.GetProviderName())
			}
			if len(req.AcmeIssuer.GetProviderConfig()) > 0 {
				updateBuilder.SetProviderConfig(req.AcmeIssuer.GetProviderConfig())
			}
			// EAB (External Account Binding) support
			if req.AcmeIssuer.EabKid != nil && *req.AcmeIssuer.EabKid != "" {
				updateBuilder.SetEabKid(*req.AcmeIssuer.EabKid)
			}
			if req.AcmeIssuer.EabHmacKey != nil && *req.AcmeIssuer.EabHmacKey != "" {
				updateBuilder.SetEabHmacKey(*req.AcmeIssuer.EabHmacKey)
			}

			_, err = updateBuilder.Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				r.log.Errorf("update acme issuer config failed: %s", err.Error())
				return nil, lcmV1.ErrorInternalServerError("update issuer configuration failed")
			}
		}
	}

	if err := tx.Commit(); err != nil {
		r.log.Errorf("commit transaction failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("update issuer failed")
	}

	return r.GetByID(ctx, id)
}

// Delete deletes an issuer by name within a tenant
func (r *IssuerRepo) Delete(ctx context.Context, tenantID uint32, name string) error {
	existingIssuer, err := r.GetByTenantAndName(ctx, tenantID, name)
	if err != nil {
		return err
	}
	if existingIssuer == nil {
		return lcmV1.ErrorNotFound("issuer not found")
	}

	tx, err := r.entClient.Client().Tx(ctx)
	if err != nil {
		r.log.Errorf("failed to start transaction: %s", err.Error())
		return lcmV1.ErrorInternalServerError("failed to delete issuer")
	}

	// Delete type-specific configurations first
	switch existingIssuer.Type {
	case issuer.TypeSelfSigned:
		_, err = tx.SelfSignedIssuer.Delete().
			Where(selfsignedissuer.HasIssuerWith(issuer.IDEQ(existingIssuer.ID))).
			Exec(ctx)
		if err != nil {
			_ = tx.Rollback()
			r.log.Errorf("delete self-signed config failed: %s", err.Error())
			return lcmV1.ErrorInternalServerError("delete issuer failed")
		}
	case issuer.TypeAcme:
		_, err = tx.AcmeIssuer.Delete().
			Where(acmeissuer.HasIssuerWith(issuer.IDEQ(existingIssuer.ID))).
			Exec(ctx)
		if err != nil {
			_ = tx.Rollback()
			r.log.Errorf("delete acme config failed: %s", err.Error())
			return lcmV1.ErrorInternalServerError("delete issuer failed")
		}
	}

	// Delete the issuer
	err = tx.Issuer.DeleteOneID(existingIssuer.ID).Exec(ctx)
	if err != nil {
		_ = tx.Rollback()
		r.log.Errorf("delete issuer failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("delete issuer failed")
	}

	if err := tx.Commit(); err != nil {
		r.log.Errorf("commit transaction failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("delete issuer failed")
	}

	return nil
}

// UpdateSelfSignedCA updates the CA certificate and key for a self-signed issuer
func (r *IssuerRepo) UpdateSelfSignedCA(ctx context.Context, selfSignedIssuerID int, caCertPEM, caKeyPEM, fingerprint string, expiresAt time.Time) error {
	_, err := r.entClient.Client().SelfSignedIssuer.UpdateOneID(selfSignedIssuerID).
		SetCaCertificatePem(caCertPEM).
		SetCaPrivateKeyPem(caKeyPEM).
		SetCaCertificateFingerprint(fingerprint).
		SetCaExpiresAt(expiresAt).
		Save(ctx)
	if err != nil {
		r.log.Errorf("update self-signed CA failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("update self-signed CA failed")
	}
	return nil
}

// UpdateACMEAccountKey updates the ACME account private key for an ACME issuer
func (r *IssuerRepo) UpdateACMEAccountKey(ctx context.Context, acmeIssuerID int, keyPEM string) error {
	_, err := r.entClient.Client().AcmeIssuer.UpdateOneID(acmeIssuerID).
		SetKeyPem(keyPEM).
		Save(ctx)
	if err != nil {
		r.log.Errorf("update ACME account key failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("update ACME account key failed")
	}
	return nil
}

// ToProto converts an ent.Issuer to lcmV1.IssuerInfo
func (r *IssuerRepo) ToProto(entity *ent.Issuer) *lcmV1.IssuerInfo {
	if entity == nil {
		return nil
	}

	proto := &lcmV1.IssuerInfo{
		Name:        entity.Name,
		Type:        string(entity.Type),
		Description: entity.Description,
		Config:      make(map[string]string),
	}

	// Map status
	if entity.Status != nil {
		status := mapEntStatusToProto(*entity.Status)
		proto.Status = &status
	}

	// Add timestamps
	if entity.CreateTime != nil {
		proto.CreateTime = timestamppb.New(*entity.CreateTime)
	}
	if entity.UpdateTime != nil {
		proto.UpdateTime = timestamppb.New(*entity.UpdateTime)
	}

	// Add type-specific config (sanitized - no secrets)
	switch entity.Type {
	case issuer.TypeSelfSigned:
		if len(entity.Edges.SelfSignedConfigs) > 0 {
			cfg := entity.Edges.SelfSignedConfigs[0]
			proto.Config["common_name"] = cfg.CommonName
			proto.Config["ca_common_name"] = cfg.CaCommonName
			if cfg.CaOrganization != "" {
				proto.Config["ca_organization"] = cfg.CaOrganization
			}
		}
	case issuer.TypeAcme:
		if len(entity.Edges.AcmeConfigs) > 0 {
			cfg := entity.Edges.AcmeConfigs[0]
			proto.Config["email"] = cfg.Email
			proto.Config["endpoint"] = cfg.Endpoint
			proto.Config["challenge_type"] = string(cfg.ChallengeType)
			if cfg.ProviderName != "" {
				proto.Config["provider_name"] = cfg.ProviderName
			}
			// Include EAB KID if set (but NOT the HMAC key for security)
			if cfg.EabKid != "" {
				proto.Config["eab_kid"] = cfg.EabKid
				proto.Config["eab_configured"] = "true"
			}
		}
	}

	return proto
}

// Helper functions for status mapping
func mapProtoStatusToEnt(status lcmV1.IssuerStatus) issuer.Status {
	switch status {
	case lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE:
		return issuer.StatusISSUER_STATUS_ACTIVE
	case lcmV1.IssuerStatus_ISSUER_STATUS_DISABLED:
		return issuer.StatusISSUER_STATUS_DISABLED
	case lcmV1.IssuerStatus_ISSUER_STATUS_ERROR:
		return issuer.StatusISSUER_STATUS_ERROR
	default:
		return issuer.StatusISSUER_STATUS_UNSPECIFIED
	}
}

func mapEntStatusToProto(status issuer.Status) lcmV1.IssuerStatus {
	switch status {
	case issuer.StatusISSUER_STATUS_ACTIVE:
		return lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE
	case issuer.StatusISSUER_STATUS_DISABLED:
		return lcmV1.IssuerStatus_ISSUER_STATUS_DISABLED
	case issuer.StatusISSUER_STATUS_ERROR:
		return lcmV1.IssuerStatus_ISSUER_STATUS_ERROR
	default:
		return lcmV1.IssuerStatus_ISSUER_STATUS_UNSPECIFIED
	}
}

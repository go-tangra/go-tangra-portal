package data

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	pagination "github.com/tx7do/go-crud/api/gen/go/pagination/v1"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/tx7do/go-utils/copierutil"
	"github.com/tx7do/go-utils/mapper"
	"github.com/tx7do/go-utils/timeutil"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/mtlscertificate"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/predicate"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

type MtlsCertificateRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper

	mapper                    *mapper.CopierMapper[lcmV1.MtlsCertificate, ent.MtlsCertificate]
	statusConverter           *mapper.EnumTypeConverter[lcmV1.MtlsCertificateStatus, mtlscertificate.Status]
	typeConverter             *mapper.EnumTypeConverter[lcmV1.MtlsCertificateType, mtlscertificate.CertType]
	revocationReasonConverter *mapper.EnumTypeConverter[lcmV1.MtlsCertificateRevocationReason, mtlscertificate.RevocationReason]

	repository *entCrud.Repository[
		ent.MtlsCertificateQuery, ent.MtlsCertificateSelect,
		ent.MtlsCertificateCreate, ent.MtlsCertificateCreateBulk,
		ent.MtlsCertificateUpdate, ent.MtlsCertificateUpdateOne,
		ent.MtlsCertificateDelete,
		predicate.MtlsCertificate,
		lcmV1.MtlsCertificate, ent.MtlsCertificate,
	]
}

func NewMtlsCertificateRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *MtlsCertificateRepo {
	repo := &MtlsCertificateRepo{
		log:                       ctx.NewLoggerHelper("mtls_certificate/repo/admin-service"),
		entClient:                 entClient,
		mapper:                    mapper.NewCopierMapper[lcmV1.MtlsCertificate, ent.MtlsCertificate](),
		statusConverter:           mapper.NewEnumTypeConverter[lcmV1.MtlsCertificateStatus, mtlscertificate.Status](lcmV1.MtlsCertificateStatus_name, lcmV1.MtlsCertificateStatus_value),
		typeConverter:             mapper.NewEnumTypeConverter[lcmV1.MtlsCertificateType, mtlscertificate.CertType](lcmV1.MtlsCertificateType_name, lcmV1.MtlsCertificateType_value),
		revocationReasonConverter: mapper.NewEnumTypeConverter[lcmV1.MtlsCertificateRevocationReason, mtlscertificate.RevocationReason](lcmV1.MtlsCertificateRevocationReason_name, lcmV1.MtlsCertificateRevocationReason_value),
	}

	repo.init()

	return repo
}

func (r *MtlsCertificateRepo) init() {
	r.repository = entCrud.NewRepository[
		ent.MtlsCertificateQuery, ent.MtlsCertificateSelect,
		ent.MtlsCertificateCreate, ent.MtlsCertificateCreateBulk,
		ent.MtlsCertificateUpdate, ent.MtlsCertificateUpdateOne,
		ent.MtlsCertificateDelete,
		predicate.MtlsCertificate,
		lcmV1.MtlsCertificate, ent.MtlsCertificate,
	](r.mapper)

	r.mapper.AppendConverters(copierutil.NewTimeStringConverterPair())
	r.mapper.AppendConverters(copierutil.NewTimeTimestamppbConverterPair())

	r.mapper.AppendConverters(r.statusConverter.NewConverterPair())
	r.mapper.AppendConverters(r.typeConverter.NewConverterPair())
	r.mapper.AppendConverters(r.revocationReasonConverter.NewConverterPair())
}

func (r *MtlsCertificateRepo) Count(ctx context.Context, whereCond []func(s *sql.Selector)) (int, error) {
	builder := r.entClient.Client().MtlsCertificate.Query()
	if len(whereCond) != 0 {
		builder.Modify(whereCond...)
	}

	count, err := builder.Count(ctx)
	if err != nil {
		r.log.Errorf("query count failed: %s", err.Error())
		return 0, lcmV1.ErrorInternalServerError("query count failed")
	}

	return count, nil
}

func (r *MtlsCertificateRepo) List(ctx context.Context, req *pagination.PagingRequest) (*lcmV1.ListMtlsCertificatesResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().MtlsCertificate.Query()

	ret, err := r.repository.ListWithPaging(ctx, builder, builder.Clone(), req)
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return &lcmV1.ListMtlsCertificatesResponse{Total: 0, Items: nil}, nil
	}

	return &lcmV1.ListMtlsCertificatesResponse{
		Total: ret.Total,
		Items: ret.Items,
	}, nil
}

func (r *MtlsCertificateRepo) ListWithFilters(ctx context.Context, req *lcmV1.ListMtlsCertificatesRequest) (*lcmV1.ListMtlsCertificatesResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().MtlsCertificate.Query()

	// Apply filters
	if req.Status != nil {
		status := r.statusConverter.ToEntity(req.Status)
		if status != nil {
			builder.Where(mtlscertificate.StatusEQ(*status))
		}
	}
	if req.ClientId != nil {
		builder.Where(mtlscertificate.ClientIDEQ(req.GetClientId()))
	}
	if req.IssuerName != nil {
		builder.Where(mtlscertificate.IssuerNameEQ(req.GetIssuerName()))
	}
	if req.CommonName != nil {
		builder.Where(mtlscertificate.CommonNameContains(req.GetCommonName()))
	}

	// Filter expired/revoked based on flags
	if req.IncludeExpired == nil || !req.GetIncludeExpired() {
		builder.Where(mtlscertificate.StatusNEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_EXPIRED))
	}
	if req.IncludeRevoked == nil || !req.GetIncludeRevoked() {
		builder.Where(mtlscertificate.StatusNEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_REVOKED))
	}

	// Apply pagination
	pagingReq := &pagination.PagingRequest{}
	if req.Page != nil {
		pagingReq.Page = req.Page
	}
	if req.PageSize != nil {
		pagingReq.PageSize = req.PageSize
	}

	ret, err := r.repository.ListWithPaging(ctx, builder, builder.Clone(), pagingReq)
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return &lcmV1.ListMtlsCertificatesResponse{Total: 0, Items: nil}, nil
	}

	return &lcmV1.ListMtlsCertificatesResponse{
		Total: ret.Total,
		Items: ret.Items,
	}, nil
}

func (r *MtlsCertificateRepo) IsExist(ctx context.Context, id uint32) (bool, error) {
	exist, err := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.IDEQ(id)).
		Exist(ctx)
	if err != nil {
		r.log.Errorf("query exist failed: %s", err.Error())
		return false, lcmV1.ErrorInternalServerError("query exist failed")
	}
	return exist, nil
}

func (r *MtlsCertificateRepo) IsExistBySerialNumber(ctx context.Context, serialNumber int64) (bool, error) {
	exist, err := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.SerialNumberEQ(serialNumber)).
		Exist(ctx)
	if err != nil {
		r.log.Errorf("query exist by serial_number failed: %s", err.Error())
		return false, lcmV1.ErrorInternalServerError("query exist failed")
	}
	return exist, nil
}

func (r *MtlsCertificateRepo) Get(ctx context.Context, req *lcmV1.GetMtlsCertificateRequest) (*lcmV1.MtlsCertificate, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().MtlsCertificate.Query()

	var whereCond []func(s *sql.Selector)
	switch req.QueryBy.(type) {
	case *lcmV1.GetMtlsCertificateRequest_SerialNumber:
		builder.Where(mtlscertificate.SerialNumberEQ(req.GetSerialNumber()))
	case *lcmV1.GetMtlsCertificateRequest_FingerprintSha256:
		builder.Where(mtlscertificate.FingerprintSha256EQ(req.GetFingerprintSha256()))
	case *lcmV1.GetMtlsCertificateRequest_CommonName:
		builder.Where(mtlscertificate.CommonNameEQ(req.GetCommonName()))
	default:
		return nil, lcmV1.ErrorBadRequest("query parameter required")
	}

	dto, err := r.repository.Get(ctx, builder, req.GetViewMask(), whereCond...)
	if err != nil {
		return nil, err
	}

	return dto, err
}

func (r *MtlsCertificateRepo) GetByID(ctx context.Context, id uint32) (*lcmV1.MtlsCertificate, error) {
	builder := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.IDEQ(id))

	entity, err := builder.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate not found")
		}
		r.log.Errorf("query certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRepo) GetBySerialNumber(ctx context.Context, serialNumber int64) (*lcmV1.MtlsCertificate, error) {
	builder := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.SerialNumberEQ(serialNumber))

	entity, err := builder.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate not found")
		}
		r.log.Errorf("query certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRepo) GetByFingerprint(ctx context.Context, fingerprintSha256 string) (*lcmV1.MtlsCertificate, error) {
	builder := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.FingerprintSha256EQ(fingerprintSha256))

	entity, err := builder.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate not found")
		}
		r.log.Errorf("query certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRepo) Issue(ctx context.Context, req *lcmV1.IssueMtlsCertificateRequest, serialNumber int64, issuedBy uint32) (*lcmV1.MtlsCertificate, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	now := time.Now()
	builder := r.entClient.Client().MtlsCertificate.Create().
		SetSerialNumber(serialNumber).
		SetClientID(req.GetClientId()).
		SetCommonName(req.GetCommonName()).
		SetStatus(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_ACTIVE).
		SetIssuedBy(issuedBy).
		SetIssuedAt(now).
		SetCreateTime(now)

	// Optional fields
	if req.CsrPem != nil {
		// CSR is used for signing but not stored directly in certificate
	}
	if req.PublicKeyPem != nil {
		builder.SetPublicKeyPem(req.GetPublicKeyPem())
	}
	if len(req.DnsNames) > 0 {
		builder.SetDNSNames(req.DnsNames)
	}
	if len(req.IpAddresses) > 0 {
		builder.SetIPAddresses(req.IpAddresses)
	}
	if req.IssuerName != nil {
		builder.SetIssuerName(req.GetIssuerName())
	}
	if req.CertType != nil {
		builder.SetNillableCertType(r.typeConverter.ToEntity(req.CertType))
	}
	if req.ValidityDays != nil {
		notBefore := now
		notAfter := now.AddDate(0, 0, int(req.GetValidityDays()))
		builder.SetNotBefore(notBefore).SetNotAfter(notAfter)
	}
	if len(req.Metadata) > 0 {
		builder.SetMetadata(req.Metadata)
	}
	if req.Notes != nil {
		builder.SetNotes(req.GetNotes())
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("issue certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("issue certificate failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRepo) Create(ctx context.Context, data *lcmV1.MtlsCertificate) (*lcmV1.MtlsCertificate, error) {
	if data == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().MtlsCertificate.Create()

	// Required field
	if data.SerialNumber != nil {
		builder.SetSerialNumber(data.GetSerialNumber())
	}

	// Optional fields
	if data.ClientId != nil {
		builder.SetClientID(data.GetClientId())
	}
	if data.CommonName != nil {
		builder.SetCommonName(data.GetCommonName())
	}
	if data.SubjectDn != nil {
		builder.SetSubjectDn(data.GetSubjectDn())
	}
	if data.IssuerDn != nil {
		builder.SetIssuerDn(data.GetIssuerDn())
	}
	if data.IssuerName != nil {
		builder.SetIssuerName(data.GetIssuerName())
	}
	if data.FingerprintSha256 != nil {
		builder.SetFingerprintSha256(data.GetFingerprintSha256())
	}
	if data.FingerprintSha1 != nil {
		builder.SetFingerprintSha1(data.GetFingerprintSha1())
	}
	if data.PublicKeyAlgorithm != nil {
		builder.SetPublicKeyAlgorithm(data.GetPublicKeyAlgorithm())
	}
	if data.PublicKeySize != nil {
		builder.SetPublicKeySize(data.GetPublicKeySize())
	}
	if data.SignatureAlgorithm != nil {
		builder.SetSignatureAlgorithm(data.GetSignatureAlgorithm())
	}
	if data.CertificatePem != nil {
		builder.SetCertificatePem(data.GetCertificatePem())
	}
	if data.PublicKeyPem != nil {
		builder.SetPublicKeyPem(data.GetPublicKeyPem())
	}
	if len(data.DnsNames) > 0 {
		builder.SetDNSNames(data.DnsNames)
	}
	if len(data.IpAddresses) > 0 {
		builder.SetIPAddresses(data.IpAddresses)
	}
	if len(data.EmailAddresses) > 0 {
		builder.SetEmailAddresses(data.EmailAddresses)
	}
	if len(data.Uris) > 0 {
		builder.SetUris(data.Uris)
	}
	if data.CertType != nil {
		builder.SetNillableCertType(r.typeConverter.ToEntity(data.CertType))
	}
	if data.Status != nil {
		builder.SetNillableStatus(r.statusConverter.ToEntity(data.Status))
	}
	if data.IsCa != nil {
		builder.SetIsCa(data.GetIsCa())
	}
	if data.PathLenConstraint != nil {
		builder.SetPathLenConstraint(data.GetPathLenConstraint())
	}
	if len(data.KeyUsage) > 0 {
		builder.SetKeyUsage(data.KeyUsage)
	}
	if len(data.ExtKeyUsage) > 0 {
		builder.SetExtKeyUsage(data.ExtKeyUsage)
	}
	if len(data.Metadata) > 0 {
		builder.SetMetadata(data.Metadata)
	}
	if data.Notes != nil {
		builder.SetNotes(data.GetNotes())
	}
	if data.RequestId != nil {
		builder.SetRequestID(data.GetRequestId())
	}
	if data.IssuedBy != nil {
		builder.SetIssuedBy(data.GetIssuedBy())
	}
	if data.NotBefore != nil {
		builder.SetNillableNotBefore(timeutil.TimestamppbToTime(data.NotBefore))
	}
	if data.NotAfter != nil {
		builder.SetNillableNotAfter(timeutil.TimestamppbToTime(data.NotAfter))
	}
	if data.IssuedAt != nil {
		builder.SetNillableIssuedAt(timeutil.TimestamppbToTime(data.IssuedAt))
	}

	if data.CreateTime == nil {
		builder.SetCreateTime(time.Now())
	} else {
		builder.SetNillableCreateTime(timeutil.TimestamppbToTime(data.CreateTime))
	}

	if data.CreatedBy != nil {
		builder.SetCreateBy(data.GetCreatedBy())
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create certificate failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRepo) Update(ctx context.Context, req *lcmV1.UpdateMtlsCertificateRequest) (*lcmV1.MtlsCertificate, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	// Find the certificate by serial number
	entity, err := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.SerialNumberEQ(req.GetSerialNumber())).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate not found")
		}
		r.log.Errorf("query certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate failed")
	}

	builder := r.entClient.Client().MtlsCertificate.UpdateOneID(entity.ID).
		SetUpdateTime(time.Now())

	// Only metadata and notes can be updated (certificate content is immutable)
	if len(req.Metadata) > 0 {
		builder.SetMetadata(req.Metadata)
	}
	if req.Notes != nil {
		builder.SetNotes(req.GetNotes())
	}

	updatedEntity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("update certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("update certificate failed")
	}

	return r.mapper.ToDTO(updatedEntity), nil
}

func (r *MtlsCertificateRepo) Revoke(ctx context.Context, req *lcmV1.RevokeMtlsCertificateRequest, revokedBy uint32) (*lcmV1.MtlsCertificate, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	// Find the certificate by serial number
	entity, err := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.SerialNumberEQ(req.GetSerialNumber())).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate not found")
		}
		r.log.Errorf("query certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate failed")
	}

	now := time.Now()
	builder := r.entClient.Client().MtlsCertificate.UpdateOneID(entity.ID).
		SetStatus(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_REVOKED).
		SetNillableRevocationReason(r.revocationReasonConverter.ToEntity(&req.Reason)).
		SetRevokedBy(revokedBy).
		SetRevokedAt(now).
		SetUpdateTime(now)

	if req.Notes != nil {
		builder.SetRevocationNotes(req.GetNotes())
	}

	updatedEntity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("revoke certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("revoke certificate failed")
	}

	return r.mapper.ToDTO(updatedEntity), nil
}

func (r *MtlsCertificateRepo) Delete(ctx context.Context, serialNumber int64) (*lcmV1.MtlsCertificate, error) {
	// Find the certificate by serial number
	entity, err := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.SerialNumberEQ(serialNumber)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate not found")
		}
		r.log.Errorf("query certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate failed")
	}

	// Soft delete by setting delete_time
	_, err = r.entClient.Client().MtlsCertificate.UpdateOneID(entity.ID).
		SetDeleteTime(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("delete certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("delete certificate failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRepo) UpdateLastSeen(ctx context.Context, serialNumber int64) error {
	// Find the certificate by serial number
	entity, err := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.SerialNumberEQ(serialNumber)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return lcmV1.ErrorNotFound("certificate not found")
		}
		r.log.Errorf("query certificate failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("query certificate failed")
	}

	_, err = r.entClient.Client().MtlsCertificate.UpdateOneID(entity.ID).
		SetLastSeenAt(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("update last seen failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("update last seen failed")
	}

	return nil
}

func (r *MtlsCertificateRepo) GetActiveCertificates(ctx context.Context, limit int) ([]*lcmV1.MtlsCertificate, error) {
	entities, err := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_ACTIVE)).
		Order(ent.Desc(mtlscertificate.FieldCreateTime)).
		Limit(limit).
		All(ctx)

	if err != nil {
		r.log.Errorf("query active certificates failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query active certificates failed")
	}

	result := make([]*lcmV1.MtlsCertificate, 0, len(entities))
	for _, entity := range entities {
		result = append(result, r.mapper.ToDTO(entity))
	}

	return result, nil
}

func (r *MtlsCertificateRepo) GetExpiringCertificates(ctx context.Context, withinDays int, limit int) ([]*lcmV1.MtlsCertificate, error) {
	expiryThreshold := time.Now().AddDate(0, 0, withinDays)

	entities, err := r.entClient.Client().MtlsCertificate.Query().
		Where(
			mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_ACTIVE),
			mtlscertificate.NotAfterLTE(expiryThreshold),
			mtlscertificate.NotAfterGT(time.Now()),
		).
		Order(ent.Asc(mtlscertificate.FieldNotAfter)).
		Limit(limit).
		All(ctx)

	if err != nil {
		r.log.Errorf("query expiring certificates failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query expiring certificates failed")
	}

	result := make([]*lcmV1.MtlsCertificate, 0, len(entities))
	for _, entity := range entities {
		result = append(result, r.mapper.ToDTO(entity))
	}

	return result, nil
}

func (r *MtlsCertificateRepo) GetCertificatesByClientID(ctx context.Context, clientID string) ([]*lcmV1.MtlsCertificate, error) {
	entities, err := r.entClient.Client().MtlsCertificate.Query().
		Where(
			mtlscertificate.ClientIDEQ(clientID),
			mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_ACTIVE),
		).
		Order(ent.Desc(mtlscertificate.FieldCreateTime)).
		All(ctx)

	if err != nil {
		r.log.Errorf("query certificates by client_id failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificates failed")
	}

	result := make([]*lcmV1.MtlsCertificate, 0, len(entities))
	for _, entity := range entities {
		result = append(result, r.mapper.ToDTO(entity))
	}

	return result, nil
}

func (r *MtlsCertificateRepo) Download(ctx context.Context, serialNumber int64, includeChain bool) (*lcmV1.DownloadMtlsCertificateResponse, error) {
	entity, err := r.entClient.Client().MtlsCertificate.Query().
		Where(mtlscertificate.SerialNumberEQ(serialNumber)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate not found")
		}
		r.log.Errorf("query certificate failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate failed")
	}

	response := &lcmV1.DownloadMtlsCertificateResponse{
		CertificatePem: entity.CertificatePem,
	}

	// TODO: If includeChain is true, fetch CA certificate chain
	// This would require looking up the issuer and building the chain

	return response, nil
}

// GetClientIDByCommonName returns the client_id for an active mTLS certificate with the given common name.
// This is used to map the certificate's CN (hostname) to the actual client_id (machine-id).
func (r *MtlsCertificateRepo) GetClientIDByCommonName(ctx context.Context, commonName string) (string, error) {
	entity, err := r.entClient.Client().MtlsCertificate.Query().
		Where(
			mtlscertificate.CommonNameEQ(commonName),
			mtlscertificate.StatusEQ(mtlscertificate.StatusMTLS_CERTIFICATE_STATUS_ACTIVE),
		).
		Order(ent.Desc(mtlscertificate.FieldCreateTime)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return "", nil // Not found is not an error
		}
		r.log.Errorf("query certificate by common_name failed: %s", err.Error())
		return "", lcmV1.ErrorInternalServerError("query certificate failed")
	}

	return entity.ClientID, nil
}

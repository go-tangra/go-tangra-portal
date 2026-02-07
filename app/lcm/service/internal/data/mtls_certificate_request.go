package data

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	pagination "github.com/tx7do/go-crud/api/gen/go/pagination/v1"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/tx7do/go-utils/copierutil"
	"github.com/tx7do/go-utils/mapper"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/mtlscertificaterequest"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/predicate"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

type MtlsCertificateRequestRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper

	mapper          *mapper.CopierMapper[lcmV1.MtlsCertificateRequest, ent.MtlsCertificateRequest]
	statusConverter *mapper.EnumTypeConverter[lcmV1.MtlsCertificateRequestStatus, mtlscertificaterequest.Status]
	typeConverter   *mapper.EnumTypeConverter[lcmV1.MtlsCertificateType, mtlscertificaterequest.CertType]

	repository *entCrud.Repository[
		ent.MtlsCertificateRequestQuery, ent.MtlsCertificateRequestSelect,
		ent.MtlsCertificateRequestCreate, ent.MtlsCertificateRequestCreateBulk,
		ent.MtlsCertificateRequestUpdate, ent.MtlsCertificateRequestUpdateOne,
		ent.MtlsCertificateRequestDelete,
		predicate.MtlsCertificateRequest,
		lcmV1.MtlsCertificateRequest, ent.MtlsCertificateRequest,
	]
}

func NewMtlsCertificateRequestRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *MtlsCertificateRequestRepo {
	repo := &MtlsCertificateRequestRepo{
		log:             ctx.NewLoggerHelper("mtls_certificate_request/repo/admin-service"),
		entClient:       entClient,
		mapper:          mapper.NewCopierMapper[lcmV1.MtlsCertificateRequest, ent.MtlsCertificateRequest](),
		statusConverter: mapper.NewEnumTypeConverter[lcmV1.MtlsCertificateRequestStatus, mtlscertificaterequest.Status](lcmV1.MtlsCertificateRequestStatus_name, lcmV1.MtlsCertificateRequestStatus_value),
		typeConverter:   mapper.NewEnumTypeConverter[lcmV1.MtlsCertificateType, mtlscertificaterequest.CertType](lcmV1.MtlsCertificateType_name, lcmV1.MtlsCertificateType_value),
	}

	repo.init()

	return repo
}

func (r *MtlsCertificateRequestRepo) init() {
	r.repository = entCrud.NewRepository[
		ent.MtlsCertificateRequestQuery, ent.MtlsCertificateRequestSelect,
		ent.MtlsCertificateRequestCreate, ent.MtlsCertificateRequestCreateBulk,
		ent.MtlsCertificateRequestUpdate, ent.MtlsCertificateRequestUpdateOne,
		ent.MtlsCertificateRequestDelete,
		predicate.MtlsCertificateRequest,
		lcmV1.MtlsCertificateRequest, ent.MtlsCertificateRequest,
	](r.mapper)

	r.mapper.AppendConverters(copierutil.NewTimeStringConverterPair())
	r.mapper.AppendConverters(copierutil.NewTimeTimestamppbConverterPair())

	r.mapper.AppendConverters(r.statusConverter.NewConverterPair())
	r.mapper.AppendConverters(r.typeConverter.NewConverterPair())
}

func (r *MtlsCertificateRequestRepo) Count(ctx context.Context, whereCond []func(s *sql.Selector)) (int, error) {
	builder := r.entClient.Client().MtlsCertificateRequest.Query()
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

func (r *MtlsCertificateRequestRepo) List(ctx context.Context, req *pagination.PagingRequest) (*lcmV1.ListMtlsCertificateRequestsResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().MtlsCertificateRequest.Query()

	ret, err := r.repository.ListWithPaging(ctx, builder, builder.Clone(), req)
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return &lcmV1.ListMtlsCertificateRequestsResponse{Total: 0, Items: nil}, nil
	}

	return &lcmV1.ListMtlsCertificateRequestsResponse{
		Total: ret.Total,
		Items: ret.Items,
	}, nil
}

func (r *MtlsCertificateRequestRepo) ListWithFilters(ctx context.Context, req *lcmV1.ListMtlsCertificateRequestsRequest) (*lcmV1.ListMtlsCertificateRequestsResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().MtlsCertificateRequest.Query()

	// Apply filters
	if req.Status != nil {
		status := r.statusConverter.ToEntity(req.Status)
		if status != nil {
			builder.Where(mtlscertificaterequest.StatusEQ(*status))
		}
	}
	if req.ClientId != nil {
		builder.Where(mtlscertificaterequest.ClientIDEQ(req.GetClientId()))
	}
	if req.IssuerName != nil {
		builder.Where(mtlscertificaterequest.IssuerNameEQ(req.GetIssuerName()))
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
		return &lcmV1.ListMtlsCertificateRequestsResponse{Total: 0, Items: nil}, nil
	}

	return &lcmV1.ListMtlsCertificateRequestsResponse{
		Total: ret.Total,
		Items: ret.Items,
	}, nil
}

func (r *MtlsCertificateRequestRepo) IsExist(ctx context.Context, id uint32) (bool, error) {
	exist, err := r.entClient.Client().MtlsCertificateRequest.Query().
		Where(mtlscertificaterequest.IDEQ(id)).
		Exist(ctx)
	if err != nil {
		r.log.Errorf("query exist failed: %s", err.Error())
		return false, lcmV1.ErrorInternalServerError("query exist failed")
	}
	return exist, nil
}

func (r *MtlsCertificateRequestRepo) IsExistByRequestID(ctx context.Context, requestID string) (bool, error) {
	exist, err := r.entClient.Client().MtlsCertificateRequest.Query().
		Where(mtlscertificaterequest.RequestIDEQ(requestID)).
		Exist(ctx)
	if err != nil {
		r.log.Errorf("query exist by request_id failed: %s", err.Error())
		return false, lcmV1.ErrorInternalServerError("query exist failed")
	}
	return exist, nil
}

func (r *MtlsCertificateRequestRepo) Get(ctx context.Context, req *lcmV1.GetMtlsCertificateRequestRequest) (*lcmV1.MtlsCertificateRequest, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().MtlsCertificateRequest.Query()

	var whereCond []func(s *sql.Selector)
	switch req.QueryBy.(type) {
	case *lcmV1.GetMtlsCertificateRequestRequest_Id:
		builder.Where(mtlscertificaterequest.IDEQ(req.GetId()))
	case *lcmV1.GetMtlsCertificateRequestRequest_RequestId:
		builder.Where(mtlscertificaterequest.RequestIDEQ(req.GetRequestId()))
	default:
		return nil, lcmV1.ErrorBadRequest("query parameter required")
	}

	dto, err := r.repository.Get(ctx, builder, req.GetViewMask(), whereCond...)
	if err != nil {
		return nil, err
	}

	return dto, err
}

func (r *MtlsCertificateRequestRepo) GetByID(ctx context.Context, id uint32) (*lcmV1.MtlsCertificateRequest, error) {
	builder := r.entClient.Client().MtlsCertificateRequest.Query().
		Where(mtlscertificaterequest.IDEQ(id))

	entity, err := builder.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("query certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate request failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRequestRepo) GetByRequestID(ctx context.Context, requestID string) (*lcmV1.MtlsCertificateRequest, error) {
	builder := r.entClient.Client().MtlsCertificateRequest.Query().
		Where(mtlscertificaterequest.RequestIDEQ(requestID))

	entity, err := builder.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("query certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate request failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRequestRepo) Create(ctx context.Context, req *lcmV1.CreateMtlsCertificateRequestRequest) (*lcmV1.MtlsCertificateRequest, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	// Generate request ID if not provided
	requestID := uuid.New().String()

	builder := r.entClient.Client().MtlsCertificateRequest.Create().
		SetRequestID(requestID).
		SetClientID(req.GetClientId()).
		SetCommonName(req.GetCommonName()).
		SetStatus(mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_PENDING).
		SetCreateTime(time.Now())

	// Optional fields
	if req.CsrPem != nil {
		builder.SetCsrPem(req.GetCsrPem())
	}
	if req.PublicKey != nil {
		builder.SetPublicKey(req.GetPublicKey())
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
		builder.SetValidityDays(req.GetValidityDays())
	}
	if len(req.Metadata) > 0 {
		builder.SetMetadata(req.Metadata)
	}
	if req.Notes != nil {
		builder.SetNotes(req.GetNotes())
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create certificate request failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRequestRepo) Update(ctx context.Context, req *lcmV1.UpdateMtlsCertificateRequestRequest) (*lcmV1.MtlsCertificateRequest, error) {
	if req == nil || req.Data == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	data := req.Data
	if data.Id == nil {
		return nil, lcmV1.ErrorBadRequest("id is required")
	}

	builder := r.entClient.Client().MtlsCertificateRequest.UpdateOneID(data.GetId()).
		SetUpdateTime(time.Now())

	// Update fields based on update mask or all fields if no mask
	if data.CommonName != nil {
		builder.SetCommonName(data.GetCommonName())
	}
	if data.CsrPem != nil {
		builder.SetCsrPem(data.GetCsrPem())
	}
	if data.PublicKey != nil {
		builder.SetPublicKey(data.GetPublicKey())
	}
	if data.DnsNames != nil {
		builder.SetDNSNames(data.DnsNames)
	}
	if data.IpAddresses != nil {
		builder.SetIPAddresses(data.IpAddresses)
	}
	if data.IssuerName != nil {
		builder.SetIssuerName(data.GetIssuerName())
	}
	if data.CertType != nil {
		builder.SetNillableCertType(r.typeConverter.ToEntity(data.CertType))
	}
	if data.Status != nil {
		builder.SetNillableStatus(r.statusConverter.ToEntity(data.Status))
	}
	if data.ValidityDays != nil {
		builder.SetValidityDays(data.GetValidityDays())
	}
	if data.RejectReason != nil {
		builder.SetRejectReason(data.GetRejectReason())
	}
	if data.Metadata != nil {
		builder.SetMetadata(data.Metadata)
	}
	if data.Notes != nil {
		builder.SetNotes(data.GetNotes())
	}
	if data.UpdatedBy != nil {
		builder.SetUpdateBy(data.GetUpdatedBy())
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("update certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("update certificate request failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRequestRepo) Delete(ctx context.Context, id uint32) (*lcmV1.MtlsCertificateRequest, error) {
	// Get the entity first to return it
	entity, err := r.entClient.Client().MtlsCertificateRequest.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("get certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("get certificate request failed")
	}

	// Soft delete by setting delete_time
	_, err = r.entClient.Client().MtlsCertificateRequest.UpdateOneID(id).
		SetDeleteTime(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("delete certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("delete certificate request failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRequestRepo) Approve(ctx context.Context, req *lcmV1.ApproveMtlsCertificateRequestRequest, approvedBy uint32) (*lcmV1.MtlsCertificateRequest, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	now := time.Now()
	builder := r.entClient.Client().MtlsCertificateRequest.UpdateOneID(req.GetId()).
		SetStatus(mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_APPROVED).
		SetApprovedBy(approvedBy).
		SetApprovedAt(now).
		SetUpdateTime(now)

	// Optional overrides
	if req.IssuerName != nil {
		builder.SetIssuerName(req.GetIssuerName())
	}
	if req.ValidityDays != nil {
		builder.SetValidityDays(req.GetValidityDays())
	}
	if req.Notes != nil {
		builder.SetNotes(req.GetNotes())
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("approve certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("approve certificate request failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRequestRepo) Reject(ctx context.Context, req *lcmV1.RejectMtlsCertificateRequestRequest, rejectedBy uint32) (*lcmV1.MtlsCertificateRequest, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("invalid parameter")
	}

	now := time.Now()
	entity, err := r.entClient.Client().MtlsCertificateRequest.UpdateOneID(req.GetId()).
		SetStatus(mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_REJECTED).
		SetRejectReason(req.GetReason()).
		SetRejectedBy(rejectedBy).
		SetRejectedAt(now).
		SetUpdateTime(now).
		Save(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("reject certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("reject certificate request failed")
	}

	return r.mapper.ToDTO(entity), nil
}

func (r *MtlsCertificateRequestRepo) UpdateCertificateSerial(ctx context.Context, id uint32, certificateSerial int64) error {
	_, err := r.entClient.Client().MtlsCertificateRequest.UpdateOneID(id).
		SetStatus(mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_ISSUED).
		SetCertificateSerial(certificateSerial).
		SetUpdateTime(time.Now()).
		Save(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("update certificate serial failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("update certificate serial failed")
	}

	return nil
}

// GetByRequestIDAndClientID retrieves a certificate request by request_id and client_id
func (r *MtlsCertificateRequestRepo) GetByRequestIDAndClientID(ctx context.Context, requestID string, clientID string) (*ent.MtlsCertificateRequest, error) {
	entity, err := r.entClient.Client().MtlsCertificateRequest.Query().
		Where(
			mtlscertificaterequest.RequestIDEQ(requestID),
			mtlscertificaterequest.ClientIDEQ(clientID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("query certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate request failed")
	}
	return entity, nil
}

// GetByTenantRequestIDAndClientID retrieves a certificate request by tenant_id, request_id, and client_id
func (r *MtlsCertificateRequestRepo) GetByTenantRequestIDAndClientID(ctx context.Context, tenantID uint32, requestID string, clientID string) (*ent.MtlsCertificateRequest, error) {
	entity, err := r.entClient.Client().MtlsCertificateRequest.Query().
		Where(
			mtlscertificaterequest.TenantIDEQ(tenantID),
			mtlscertificaterequest.RequestIDEQ(requestID),
			mtlscertificaterequest.ClientIDEQ(clientID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("query certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate request failed")
	}
	return entity, nil
}

// GetEntityByRequestID retrieves the raw entity by request_id
func (r *MtlsCertificateRequestRepo) GetEntityByRequestID(ctx context.Context, requestID string) (*ent.MtlsCertificateRequest, error) {
	entity, err := r.entClient.Client().MtlsCertificateRequest.Query().
		Where(mtlscertificaterequest.RequestIDEQ(requestID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, lcmV1.ErrorNotFound("certificate request not found")
		}
		r.log.Errorf("query certificate request failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query certificate request failed")
	}
	return entity, nil
}

// CreateFromRegistration creates a certificate request from client registration
func (r *MtlsCertificateRequestRepo) CreateFromRegistration(ctx context.Context, tenantID uint32, clientID string, hostname string, publicKey string, dnsNames []string, ipAddresses []string, metadata map[string]string) (*ent.MtlsCertificateRequest, error) {
	requestID := uuid.New().String()

	builder := r.entClient.Client().MtlsCertificateRequest.Create().
		SetTenantID(tenantID).
		SetRequestID(requestID).
		SetClientID(clientID).
		SetCommonName(hostname).
		SetPublicKey(publicKey).
		SetStatus(mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_PENDING).
		SetCertType(mtlscertificaterequest.CertTypeMTLS_CERT_TYPE_CLIENT).
		SetCreateTime(time.Now())

	if len(dnsNames) > 0 {
		builder.SetDNSNames(dnsNames)
	}
	if len(ipAddresses) > 0 {
		builder.SetIPAddresses(ipAddresses)
	}
	if len(metadata) > 0 {
		builder.SetMetadata(metadata)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create certificate request from registration failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create certificate request failed")
	}

	return entity, nil
}

// MarkAsIssued marks a certificate request as issued with the certificate serial
func (r *MtlsCertificateRequestRepo) MarkAsIssued(ctx context.Context, id uint32, certificateSerial int64) error {
	_, err := r.entClient.Client().MtlsCertificateRequest.UpdateOneID(id).
		SetStatus(mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_ISSUED).
		SetCertificateSerial(certificateSerial).
		SetUpdateTime(time.Now()).
		Save(ctx)
	if err != nil {
		r.log.Errorf("mark request as issued failed: %s", err.Error())
		return lcmV1.ErrorInternalServerError("mark request as issued failed")
	}
	return nil
}

func (r *MtlsCertificateRequestRepo) GetPendingRequests(ctx context.Context, limit int) ([]*lcmV1.MtlsCertificateRequest, error) {
	entities, err := r.entClient.Client().MtlsCertificateRequest.Query().
		Where(mtlscertificaterequest.StatusEQ(mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_PENDING)).
		Order(ent.Asc(mtlscertificaterequest.FieldCreateTime)).
		Limit(limit).
		All(ctx)

	if err != nil {
		r.log.Errorf("query pending requests failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query pending requests failed")
	}

	result := make([]*lcmV1.MtlsCertificateRequest, 0, len(entities))
	for _, entity := range entities {
		result = append(result, r.mapper.ToDTO(entity))
	}

	return result, nil
}

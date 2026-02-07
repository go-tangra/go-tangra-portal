package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/auditlog"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

type AuditLogRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewAuditLogRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *AuditLogRepo {
	return &AuditLogRepo{
		log:       ctx.NewLoggerHelper("audit_log/repo"),
		entClient: entClient,
	}
}

// Create creates a new audit log entry
func (r *AuditLogRepo) Create(ctx context.Context, log *AuditLogEntry) (*ent.AuditLog, error) {
	builder := r.entClient.Client().AuditLog.Create().
		SetAuditID(log.AuditID).
		SetOperation(log.Operation).
		SetServiceName(log.ServiceName).
		SetSuccess(log.Success).
		SetIsAuthenticated(log.IsAuthenticated).
		SetLatencyMs(log.LatencyMs).
		SetCreateTime(log.Timestamp)

	if log.TenantID > 0 {
		builder.SetTenantID(log.TenantID)
	}
	if log.RequestID != "" {
		builder.SetRequestID(log.RequestID)
	}
	if log.ClientID != "" {
		builder.SetClientID(log.ClientID)
	}
	if log.ClientCommonName != "" {
		builder.SetClientCommonName(log.ClientCommonName)
	}
	if log.ClientOrganization != "" {
		builder.SetClientOrganization(log.ClientOrganization)
	}
	if log.ClientSerialNumber != "" {
		builder.SetClientSerialNumber(log.ClientSerialNumber)
	}
	if log.ErrorCode != 0 {
		builder.SetErrorCode(log.ErrorCode)
	}
	if log.ErrorMessage != "" {
		builder.SetErrorMessage(log.ErrorMessage)
	}
	if log.PeerAddress != "" {
		builder.SetPeerAddress(log.PeerAddress)
	}
	if log.GeoLocation != nil {
		builder.SetGeoLocation(log.GeoLocation)
	}
	if log.LogHash != "" {
		builder.SetLogHash(log.LogHash)
	}
	if log.Signature != nil {
		builder.SetSignature(log.Signature)
	}
	if log.Metadata != nil {
		builder.SetMetadata(log.Metadata)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create audit log failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create audit log failed")
	}

	return entity, nil
}

// GetByAuditID retrieves an audit log by its audit ID
func (r *AuditLogRepo) GetByAuditID(ctx context.Context, auditID string) (*ent.AuditLog, error) {
	entity, err := r.entClient.Client().AuditLog.Query().
		Where(auditlog.AuditIDEQ(auditID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get audit log failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("get audit log failed")
	}
	return entity, nil
}

// GetByID retrieves an audit log by ID
func (r *AuditLogRepo) GetByID(ctx context.Context, id uint32) (*ent.AuditLog, error) {
	entity, err := r.entClient.Client().AuditLog.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get audit log failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("get audit log failed")
	}
	return entity, nil
}

// ListOptions contains options for listing audit logs
type AuditLogListOptions struct {
	TenantID    *uint32
	ClientID    *string
	Operation   *string
	Success     *bool
	PeerAddress *string
	StartTime   *time.Time
	EndTime     *time.Time
	Limit       int
	Offset      int
}

// List retrieves audit logs with filtering options
func (r *AuditLogRepo) List(ctx context.Context, opts *AuditLogListOptions) ([]*ent.AuditLog, int, error) {
	query := r.entClient.Client().AuditLog.Query()

	// Apply filters
	if opts != nil {
		if opts.TenantID != nil {
			query = query.Where(auditlog.TenantIDEQ(*opts.TenantID))
		}
		if opts.ClientID != nil {
			query = query.Where(auditlog.ClientIDEQ(*opts.ClientID))
		}
		if opts.Operation != nil {
			query = query.Where(auditlog.OperationContains(*opts.Operation))
		}
		if opts.Success != nil {
			query = query.Where(auditlog.SuccessEQ(*opts.Success))
		}
		if opts.PeerAddress != nil {
			query = query.Where(auditlog.PeerAddressEQ(*opts.PeerAddress))
		}
		if opts.StartTime != nil {
			query = query.Where(auditlog.CreateTimeGTE(*opts.StartTime))
		}
		if opts.EndTime != nil {
			query = query.Where(auditlog.CreateTimeLTE(*opts.EndTime))
		}
	}

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count audit logs failed: %s", err.Error())
		return nil, 0, lcmV1.ErrorInternalServerError("count audit logs failed")
	}

	// Apply pagination
	query = query.Order(ent.Desc(auditlog.FieldCreateTime))
	if opts != nil {
		if opts.Limit > 0 {
			query = query.Limit(opts.Limit)
		}
		if opts.Offset > 0 {
			query = query.Offset(opts.Offset)
		}
	}

	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list audit logs failed: %s", err.Error())
		return nil, 0, lcmV1.ErrorInternalServerError("list audit logs failed")
	}

	return entities, total, nil
}

// ListByTenantID retrieves all audit logs for a specific tenant
func (r *AuditLogRepo) ListByTenantID(ctx context.Context, tenantID uint32, limit, offset int) ([]*ent.AuditLog, int, error) {
	return r.List(ctx, &AuditLogListOptions{
		TenantID: &tenantID,
		Limit:    limit,
		Offset:   offset,
	})
}

// ListByClientID retrieves all audit logs for a specific client
func (r *AuditLogRepo) ListByClientID(ctx context.Context, clientID string, limit, offset int) ([]*ent.AuditLog, int, error) {
	return r.List(ctx, &AuditLogListOptions{
		ClientID: &clientID,
		Limit:    limit,
		Offset:   offset,
	})
}

// ListByOperation retrieves all audit logs for a specific operation
func (r *AuditLogRepo) ListByOperation(ctx context.Context, operation string, limit, offset int) ([]*ent.AuditLog, int, error) {
	return r.List(ctx, &AuditLogListOptions{
		Operation: &operation,
		Limit:     limit,
		Offset:    offset,
	})
}

// ListFailed retrieves all failed audit logs
func (r *AuditLogRepo) ListFailed(ctx context.Context, limit, offset int) ([]*ent.AuditLog, int, error) {
	success := false
	return r.List(ctx, &AuditLogListOptions{
		Success: &success,
		Limit:   limit,
		Offset:  offset,
	})
}

// DeleteOlderThan deletes audit logs older than the specified time
func (r *AuditLogRepo) DeleteOlderThan(ctx context.Context, before time.Time) (int, error) {
	deleted, err := r.entClient.Client().AuditLog.Delete().
		Where(auditlog.CreateTimeLT(before)).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete old audit logs failed: %s", err.Error())
		return 0, lcmV1.ErrorInternalServerError("delete old audit logs failed")
	}
	return deleted, nil
}

// AuditLogEntry is the input structure for creating audit logs
type AuditLogEntry struct {
	AuditID            string
	RequestID          string
	TenantID           uint32
	Operation          string
	ServiceName        string
	ClientID           string
	ClientCommonName   string
	ClientOrganization string
	ClientSerialNumber string
	IsAuthenticated    bool
	Success            bool
	ErrorCode          int32
	ErrorMessage       string
	LatencyMs          int64
	PeerAddress        string
	GeoLocation        map[string]string
	LogHash            string
	Signature          []byte
	Metadata           map[string]string
	Timestamp          time.Time
}

// ToProto converts an ent.AuditLog to lcmV1.AuditLog
func (r *AuditLogRepo) ToProto(entity *ent.AuditLog) *lcmV1.AuditLog {
	if entity == nil {
		return nil
	}

	proto := &lcmV1.AuditLog{
		Id:              &entity.ID,
		AuditId:         &entity.AuditID,
		Operation:       &entity.Operation,
		ServiceName:     &entity.ServiceName,
		Success:         &entity.Success,
		IsAuthenticated: &entity.IsAuthenticated,
		LatencyMs:       &entity.LatencyMs,
	}

	if entity.TenantID != nil && *entity.TenantID > 0 {
		proto.TenantId = entity.TenantID
	}
	if entity.RequestID != "" {
		proto.RequestId = &entity.RequestID
	}
	if entity.ClientID != "" {
		proto.ClientId = &entity.ClientID
	}
	if entity.ClientCommonName != "" {
		proto.ClientCommonName = &entity.ClientCommonName
	}
	if entity.ClientOrganization != "" {
		proto.ClientOrganization = &entity.ClientOrganization
	}
	if entity.ClientSerialNumber != "" {
		proto.ClientSerialNumber = &entity.ClientSerialNumber
	}
	if entity.ErrorCode != nil {
		proto.ErrorCode = entity.ErrorCode
	}
	if entity.ErrorMessage != "" {
		proto.ErrorMessage = &entity.ErrorMessage
	}
	if entity.PeerAddress != "" {
		proto.PeerAddress = &entity.PeerAddress
	}
	if entity.LogHash != "" {
		proto.LogHash = &entity.LogHash
	}

	// Convert timestamps
	if entity.CreateTime != nil && !entity.CreateTime.IsZero() {
		proto.CreatedAt = timestamppb.New(*entity.CreateTime)
	}

	return proto
}

// ToProtoList converts a slice of ent.AuditLog to lcmV1.AuditLog
func (r *AuditLogRepo) ToProtoList(entities []*ent.AuditLog) []*lcmV1.AuditLog {
	protos := make([]*lcmV1.AuditLog, len(entities))
	for i, entity := range entities {
		protos[i] = r.ToProto(entity)
	}
	return protos
}

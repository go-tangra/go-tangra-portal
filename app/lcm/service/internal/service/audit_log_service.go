package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

// AuditLogService implements the AuditLogService gRPC service
type AuditLogService struct {
	lcmV1.UnimplementedAuditLogServiceServer

	log          *log.Helper
	auditLogRepo *data.AuditLogRepo
	clientRepo   *data.LcmClientRepo
}

// NewAuditLogService creates a new AuditLogService
func NewAuditLogService(
	ctx *bootstrap.Context,
	auditLogRepo *data.AuditLogRepo,
	clientRepo *data.LcmClientRepo,
) *AuditLogService {
	return &AuditLogService{
		log:          ctx.NewLoggerHelper("lcm/service/audit_log"),
		auditLogRepo: auditLogRepo,
		clientRepo:   clientRepo,
	}
}

// getClientTenantID extracts the tenant ID from the authenticated client
// and sets it in the context for audit logging
func (s *AuditLogService) getClientTenantID(ctx context.Context) (uint32, error) {
	clientID := client.GetClientID(ctx)
	if clientID == "" {
		return 0, lcmV1.ErrorUnauthorized("client authentication required")
	}

	// First try to find client with tenant_id = 0 (platform-level clients)
	lcmClient, err := s.clientRepo.GetByTenantAndClientID(ctx, 0, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, lcmV1.ErrorInternalServerError("failed to lookup client")
	}

	if lcmClient != nil {
		if lcmClient.TenantID != nil {
			client.SetTenantIDInPlace(ctx, *lcmClient.TenantID)
			return *lcmClient.TenantID, nil
		}
		return 0, nil
	}

	// Fallback: search by client_id across tenants
	allClients, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, lcmV1.ErrorInternalServerError("failed to lookup client")
	}
	if allClients == nil {
		return 0, lcmV1.ErrorNotFound("client not registered")
	}

	if allClients.TenantID != nil {
		client.SetTenantIDInPlace(ctx, *allClients.TenantID)
		return *allClients.TenantID, nil
	}
	return 0, nil
}

// ListAuditLogs lists audit logs with filtering and pagination
func (s *AuditLogService) ListAuditLogs(ctx context.Context, req *lcmV1.ListAuditLogsRequest) (*lcmV1.ListAuditLogsResponse, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	// Build list options from request
	opts := &data.AuditLogListOptions{
		Limit:  50, // Default limit
		Offset: 0,
	}

	// Apply tenant filter (clients can only see their tenant's logs)
	if tenantID > 0 {
		opts.TenantID = &tenantID
	} else if req.TenantId != nil {
		// Platform-level clients can filter by tenant
		opts.TenantID = req.TenantId
	}

	// Apply other filters from request
	if req.ClientId != nil {
		opts.ClientID = req.ClientId
	}
	if req.Operation != nil {
		opts.Operation = req.Operation
	}
	if req.Success != nil {
		opts.Success = req.Success
	}
	if req.PeerAddress != nil {
		opts.PeerAddress = req.PeerAddress
	}
	if req.StartTime != nil {
		t := req.StartTime.AsTime()
		opts.StartTime = &t
	}
	if req.EndTime != nil {
		t := req.EndTime.AsTime()
		opts.EndTime = &t
	}

	// Pagination
	if req.PageSize != nil && *req.PageSize > 0 {
		opts.Limit = int(*req.PageSize)
		if opts.Limit > 1000 {
			opts.Limit = 1000 // Max limit
		}
	}
	if req.Page != nil && *req.Page > 0 {
		opts.Offset = (int(*req.Page) - 1) * opts.Limit
	}

	// Query database
	logs, total, err := s.auditLogRepo.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &lcmV1.ListAuditLogsResponse{
		Items: s.auditLogRepo.ToProtoList(logs),
		Total: uint64(total),
	}, nil
}

// GetAuditLog gets a single audit log by database ID
func (s *AuditLogService) GetAuditLog(ctx context.Context, req *lcmV1.GetAuditLogRequest) (*lcmV1.GetAuditLogResponse, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	auditLog, err := s.auditLogRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if auditLog == nil {
		return nil, lcmV1.ErrorNotFound("audit log not found")
	}

	// Verify tenant access
	if tenantID > 0 && (auditLog.TenantID == nil || *auditLog.TenantID != tenantID) {
		return nil, lcmV1.ErrorNotFound("audit log not found")
	}

	return &lcmV1.GetAuditLogResponse{
		AuditLog: s.auditLogRepo.ToProto(auditLog),
	}, nil
}

// GetAuditLogByAuditId gets a single audit log by audit ID (UUID)
func (s *AuditLogService) GetAuditLogByAuditId(ctx context.Context, req *lcmV1.GetAuditLogByAuditIdRequest) (*lcmV1.GetAuditLogByAuditIdResponse, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	auditLog, err := s.auditLogRepo.GetByAuditID(ctx, req.AuditId)
	if err != nil {
		return nil, err
	}
	if auditLog == nil {
		return nil, lcmV1.ErrorNotFound("audit log not found")
	}

	// Verify tenant access
	if tenantID > 0 && (auditLog.TenantID == nil || *auditLog.TenantID != tenantID) {
		return nil, lcmV1.ErrorNotFound("audit log not found")
	}

	return &lcmV1.GetAuditLogByAuditIdResponse{
		AuditLog: s.auditLogRepo.ToProto(auditLog),
	}, nil
}

// GetAuditStats gets audit statistics
func (s *AuditLogService) GetAuditStats(ctx context.Context, req *lcmV1.GetAuditStatsRequest) (*lcmV1.GetAuditStatsResponse, error) {
	tenantID, err := s.getClientTenantID(ctx)
	if err != nil {
		return nil, err
	}

	// Build options from request
	opts := &data.AuditLogListOptions{
		Limit: 0, // Get all for stats
	}

	// Apply tenant filter
	if tenantID > 0 {
		opts.TenantID = &tenantID
	} else if req.TenantId != nil {
		opts.TenantID = req.TenantId
	}

	if req.StartTime != nil {
		t := req.StartTime.AsTime()
		opts.StartTime = &t
	}
	if req.EndTime != nil {
		t := req.EndTime.AsTime()
		opts.EndTime = &t
	}

	// Get all logs for statistics (with a reasonable limit)
	opts.Limit = 10000
	logs, total, err := s.auditLogRepo.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Calculate statistics
	stats := &lcmV1.GetAuditStatsResponse{
		TotalOperations: uint64(total),
		OperationsByType: make(map[string]uint64),
	}

	var successCount, failCount uint64
	var totalLatency int64
	uniqueClients := make(map[string]struct{})

	for _, log := range logs {
		if log.Success {
			successCount++
		} else {
			failCount++
		}
		totalLatency += log.LatencyMs

		if log.ClientID != "" {
			uniqueClients[log.ClientID] = struct{}{}
		}

		// Count by operation type
		stats.OperationsByType[log.Operation]++
	}

	stats.SuccessfulOperations = successCount
	stats.FailedOperations = failCount
	stats.UniqueClients = uint64(len(uniqueClients))

	if len(logs) > 0 {
		stats.AvgLatencyMs = float64(totalLatency) / float64(len(logs))
	}

	return stats, nil
}

package audit

import (
	"context"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/event"
)

// AuditEventType is the topic for audit log events
const AuditEventType = "lcm.audit.logged"

// AuditLogEvent is published when an audit log is created
type AuditLogEvent struct {
	AuditID     string `json:"audit_id"`
	Operation   string `json:"operation"`
	ClientID    string `json:"client_id"`
	TenantID    uint32 `json:"tenant_id"`
	Success     bool   `json:"success"`
	LatencyMs   int64  `json:"latency_ms"`
	PeerAddress string `json:"peer_address,omitempty"`
	LogHash     string `json:"log_hash,omitempty"`
}

// NewEventPublisherWriter creates a WriteAuditLogFunc that publishes to the event system
func NewEventPublisherWriter(publisher *event.Publisher) WriteAuditLogFunc {
	return func(ctx context.Context, log *AuditLog) error {
		if publisher == nil || !publisher.IsEnabled() {
			return nil
		}

		auditEvent := &AuditLogEvent{
			AuditID:     log.ID,
			Operation:   log.Operation,
			ClientID:    log.ClientID,
			TenantID:    log.TenantID,
			Success:     log.Success,
			LatencyMs:   log.LatencyMs,
			PeerAddress: log.PeerAddress,
			LogHash:     log.LogHash,
		}

		return publisher.Publish(ctx, AuditEventType, auditEvent)
	}
}

// NewDatabaseWriter creates a WriteAuditLogFunc that writes to the database
func NewDatabaseWriter(repo *data.AuditLogRepo) WriteAuditLogFunc {
	return func(ctx context.Context, log *AuditLog) error {
		if repo == nil {
			return nil
		}

		// Convert audit log to database entry
		entry := &data.AuditLogEntry{
			AuditID:            log.ID,
			RequestID:          log.RequestID,
			TenantID:           log.TenantID,
			Operation:          log.Operation,
			ServiceName:        log.ServiceName,
			ClientID:           log.ClientID,
			ClientCommonName:   log.ClientCommonName,
			ClientOrganization: log.ClientOrganization,
			ClientSerialNumber: log.ClientSerialNumber,
			IsAuthenticated:    log.IsAuthenticated,
			Success:            log.Success,
			ErrorCode:          log.ErrorCode,
			ErrorMessage:       log.ErrorMessage,
			LatencyMs:          log.LatencyMs,
			PeerAddress:        log.PeerAddress,
			LogHash:            log.LogHash,
			Signature:          log.Signature,
			Metadata:           log.Metadata,
			Timestamp:          log.Timestamp,
		}

		// Convert GeoLocation to map if present
		if log.GeoLocation != nil {
			entry.GeoLocation = map[string]string{
				"country_code": log.GeoLocation.CountryCode,
				"province":     log.GeoLocation.Province,
				"city":         log.GeoLocation.City,
				"isp":          log.GeoLocation.ISP,
			}
		}

		_, err := repo.Create(ctx, entry)
		return err
	}
}

// CombinedWriter combines multiple WriteAuditLogFunc into one
func CombinedWriter(writers ...WriteAuditLogFunc) WriteAuditLogFunc {
	return func(ctx context.Context, log *AuditLog) error {
		var lastErr error
		for _, w := range writers {
			if w != nil {
				if err := w(ctx, log); err != nil {
					lastErr = err
				}
			}
		}
		return lastErr
	}
}

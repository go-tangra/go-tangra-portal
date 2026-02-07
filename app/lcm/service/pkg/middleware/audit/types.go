package audit

import (
	"time"
)

// AuditLog represents a single audit log entry for LCM operations
type AuditLog struct {
	// Identifiers
	ID        string `json:"id"`
	RequestID string `json:"request_id,omitempty"`

	// Timing
	Timestamp time.Time `json:"timestamp"`
	LatencyMs int64     `json:"latency_ms"`

	// Operation info
	Operation   string `json:"operation"`
	ServiceName string `json:"service_name"`

	// Client info (from mTLS)
	ClientID           string `json:"client_id,omitempty"`
	ClientCommonName   string `json:"client_common_name,omitempty"`
	ClientOrganization string `json:"client_organization,omitempty"`
	ClientSerialNumber string `json:"client_serial_number,omitempty"`
	IsAuthenticated    bool   `json:"is_authenticated"`

	// Tenant info
	TenantID uint32 `json:"tenant_id,omitempty"`

	// Request/Response
	Success      bool   `json:"success"`
	ErrorCode    int32  `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`

	// Network info
	PeerAddress string `json:"peer_address,omitempty"`

	// Geo location (optional)
	GeoLocation *GeoLocation `json:"geo_location,omitempty"`

	// Cryptographic integrity
	LogHash   string `json:"log_hash,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	// Additional metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// GeoLocation represents geographic location information
type GeoLocation struct {
	CountryCode string `json:"country_code,omitempty"`
	Province    string `json:"province,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
}

// SignContent is the structure used for signature generation
// It contains the critical fields that must not be tampered with
type SignContent struct {
	TenantID  uint32 `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	Operation string `json:"operation"`
	Timestamp int64  `json:"timestamp"` // Unix nanoseconds
	LogHash   string `json:"log_hash"`
}

package webhook

import (
	"time"
)

// WebhookEvent represents the envelope for all webhook events
type WebhookEvent struct {
	ID        string      `json:"id"`
	Type      string      `json:"type"`
	Source    string      `json:"source"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Event type constants mapping Redis pub/sub topics to webhook event types
const (
	EventSource = "lcm-service"

	// Certificate events
	EventCertificateRequested  = "certificate.requested"
	EventCertificateProcessing = "certificate.processing"
	EventCertificateIssued     = "certificate.issued"
	EventCertificateFailed     = "certificate.failed"
	EventCertificateCancelled  = "certificate.cancelled"

	// Renewal events
	EventRenewalScheduled = "renewal.scheduled"
	EventRenewalStarted   = "renewal.started"
	EventRenewalCompleted = "renewal.completed"
	EventRenewalFailed    = "renewal.failed"
)

// TopicToEventType maps Redis pub/sub topics to webhook event types
var TopicToEventType = map[string]string{
	"lcm.certificate.requested":  EventCertificateRequested,
	"lcm.certificate.processing": EventCertificateProcessing,
	"lcm.certificate.issued":     EventCertificateIssued,
	"lcm.certificate.failed":     EventCertificateFailed,
	"lcm.certificate.cancelled":  EventCertificateCancelled,
	"lcm.renewal.scheduled":      EventRenewalScheduled,
	"lcm.renewal.started":        EventRenewalStarted,
	"lcm.renewal.completed":      EventRenewalCompleted,
	"lcm.renewal.failed":         EventRenewalFailed,
}

// AllEventTypes returns all supported webhook event types
func AllEventTypes() []string {
	return []string{
		EventCertificateRequested,
		EventCertificateProcessing,
		EventCertificateIssued,
		EventCertificateFailed,
		EventCertificateCancelled,
		EventRenewalScheduled,
		EventRenewalStarted,
		EventRenewalCompleted,
		EventRenewalFailed,
	}
}

// CertificateEventData represents certificate-related event data
type CertificateEventData struct {
	JobID        string    `json:"job_id"`
	ClientID     string    `json:"client_id"`
	TenantID     uint32    `json:"tenant_id"`
	IssuerName   string    `json:"issuer_name"`
	SerialNumber string    `json:"serial_number,omitempty"`
	CommonName   string    `json:"common_name"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	IssuedAt     time.Time `json:"issued_at,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// RenewalEventData represents renewal-related event data
type RenewalEventData struct {
	RenewalID       int       `json:"renewal_id"`
	CertificateID   string    `json:"certificate_id"`
	ClientID        string    `json:"client_id"`
	TenantID        uint32    `json:"tenant_id"`
	IssuerName      string    `json:"issuer_name,omitempty"`
	NewSerialNumber string    `json:"new_serial_number,omitempty"`
	ScheduledAt     time.Time `json:"scheduled_at,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
	NewExpiresAt    time.Time `json:"new_expires_at,omitempty"`
	AttemptNumber   int32     `json:"attempt_number,omitempty"`
	MaxAttempts     int32     `json:"max_attempts,omitempty"`
	WillRetry       bool      `json:"will_retry,omitempty"`
	ErrorMessage    string    `json:"error_message,omitempty"`
}

// DeliveryResult represents the result of a webhook delivery attempt
type DeliveryResult struct {
	EndpointName string
	URL          string
	StatusCode   int
	Success      bool
	Error        error
	Duration     time.Duration
	Attempts     int
}

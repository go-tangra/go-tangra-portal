package event

import (
	"time"
)

// LCM Event Types - these are the topic suffixes (prefix is added by publisher)
const (
	// Client events
	TopicClientRegistered = "client.registered"
	TopicClientUpdated    = "client.updated"

	// Certificate request events
	TopicCertificateRequested  = "certificate.requested"
	TopicCertificateProcessing = "certificate.processing"
	TopicCertificateIssued     = "certificate.issued"
	TopicCertificateFailed     = "certificate.failed"
	TopicCertificateCancelled  = "certificate.cancelled"

	// Certificate renewal events
	TopicRenewalScheduled = "renewal.scheduled"
	TopicRenewalStarted   = "renewal.started"
	TopicRenewalCompleted = "renewal.completed"
	TopicRenewalFailed    = "renewal.failed"

	// Issuer events
	TopicIssuerCreated = "issuer.created"
	TopicIssuerUpdated = "issuer.updated"
	TopicIssuerDeleted = "issuer.deleted"

	// Tenant secret events
	TopicTenantSecretCreated = "tenant_secret.created"
	TopicTenantSecretRotated = "tenant_secret.rotated"
	TopicTenantSecretDeleted = "tenant_secret.deleted"
)

// Event source identifier
const EventSource = "lcm-service"

// LCMEvent is the base event structure for all LCM events
type LCMEvent struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Source    string            `json:"source"`
	Timestamp time.Time         `json:"timestamp"`
	TenantID  uint32            `json:"tenant_id"`
	Data      interface{}       `json:"data"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ClientRegisteredEvent is published when a new client registers
type ClientRegisteredEvent struct {
	ClientID    string            `json:"client_id"`
	TenantID    uint32            `json:"tenant_id"`
	Hostname    string            `json:"hostname,omitempty"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CertificateRequestedEvent is published when a certificate is requested
type CertificateRequestedEvent struct {
	JobID       string   `json:"job_id"`
	ClientID    string   `json:"client_id"`
	TenantID    uint32   `json:"tenant_id"`
	IssuerName  string   `json:"issuer_name"`
	IssuerType  string   `json:"issuer_type"`
	CommonName  string   `json:"common_name"`
	DNSNames    []string `json:"dns_names,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
}

// CertificateIssuedEvent is published when a certificate is successfully issued
type CertificateIssuedEvent struct {
	JobID        string    `json:"job_id"`
	ClientID     string    `json:"client_id"`
	TenantID     uint32    `json:"tenant_id"`
	IssuerName   string    `json:"issuer_name"`
	IssuerType   string    `json:"issuer_type"`
	SerialNumber string    `json:"serial_number"`
	CommonName   string    `json:"common_name"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`

	// Subject fields for certificate matching
	SubjectOrganization string `json:"subject_organization,omitempty"`
	SubjectOrgUnit      string `json:"subject_org_unit,omitempty"`
	SubjectCountry      string `json:"subject_country,omitempty"`
}

// CertificateFailedEvent is published when certificate issuance fails
type CertificateFailedEvent struct {
	JobID        string `json:"job_id"`
	ClientID     string `json:"client_id"`
	TenantID     uint32 `json:"tenant_id"`
	IssuerName   string `json:"issuer_name"`
	IssuerType   string `json:"issuer_type"`
	CommonName   string `json:"common_name"`
	ErrorMessage string `json:"error_message"`
}

// CertificateCancelledEvent is published when a certificate request is cancelled
type CertificateCancelledEvent struct {
	JobID    string `json:"job_id"`
	ClientID string `json:"client_id"`
	TenantID uint32 `json:"tenant_id"`
}

// RenewalScheduledEvent is published when a certificate renewal is scheduled
type RenewalScheduledEvent struct {
	RenewalID     int       `json:"renewal_id"`
	CertificateID string    `json:"certificate_id"`
	ClientID      string    `json:"client_id"`
	TenantID      uint32    `json:"tenant_id"`
	IssuerName    string    `json:"issuer_name"`
	ScheduledAt   time.Time `json:"scheduled_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// RenewalCompletedEvent is published when a certificate renewal completes
type RenewalCompletedEvent struct {
	RenewalID        int       `json:"renewal_id"`
	CertificateID    string    `json:"certificate_id"`
	ClientID         string    `json:"client_id"`
	TenantID         uint32    `json:"tenant_id"`
	NewSerialNumber  string    `json:"new_serial_number"`
	NewExpiresAt     time.Time `json:"new_expires_at"`
	AttemptNumber    int32     `json:"attempt_number"`
}

// RenewalFailedEvent is published when a certificate renewal fails
type RenewalFailedEvent struct {
	RenewalID     int    `json:"renewal_id"`
	CertificateID string `json:"certificate_id"`
	ClientID      string `json:"client_id"`
	TenantID      uint32 `json:"tenant_id"`
	ErrorMessage  string `json:"error_message"`
	AttemptNumber int32  `json:"attempt_number"`
	MaxAttempts   int32  `json:"max_attempts"`
	WillRetry     bool   `json:"will_retry"`
}

// IssuerCreatedEvent is published when a new issuer is created
type IssuerCreatedEvent struct {
	IssuerID    uint32 `json:"issuer_id"`
	TenantID    uint32 `json:"tenant_id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// IssuerUpdatedEvent is published when an issuer is updated
type IssuerUpdatedEvent struct {
	IssuerID    uint32 `json:"issuer_id"`
	TenantID    uint32 `json:"tenant_id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// IssuerDeletedEvent is published when an issuer is deleted
type IssuerDeletedEvent struct {
	IssuerID uint32 `json:"issuer_id"`
	TenantID uint32 `json:"tenant_id"`
	Name     string `json:"name"`
}

// TenantSecretCreatedEvent is published when a tenant secret is created
type TenantSecretCreatedEvent struct {
	SecretID    uint32 `json:"secret_id"`
	TenantID    uint32 `json:"tenant_id"`
	Description string `json:"description,omitempty"`
}

// TenantSecretRotatedEvent is published when a tenant secret is rotated
type TenantSecretRotatedEvent struct {
	OldSecretID uint32 `json:"old_secret_id"`
	NewSecretID uint32 `json:"new_secret_id"`
	TenantID    uint32 `json:"tenant_id"`
	OldDisabled bool   `json:"old_disabled"`
}

// TenantSecretDeletedEvent is published when a tenant secret is deleted
type TenantSecretDeletedEvent struct {
	SecretID uint32 `json:"secret_id"`
	TenantID uint32 `json:"tenant_id"`
}

package biz

import (
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
)

// JobStatus represents the status of a certificate signing job
type JobStatus string

const (
	JobStatusPending    JobStatus = "pending"
	JobStatusProcessing JobStatus = "processing"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
)

// CertificateJob represents a certificate signing job in progress
type CertificateJob struct {
	ID          string                 // Unique job ID
	TenantID    uint32                 // Tenant that owns this job
	ClientID    string                 // Associated client
	IssuerName  string                 // Name of the issuer to use
	IssuerType  string                 // self-signed, acme, etc.
	DNSNames    []string               // Certificate domains
	IPAddresses []string               // Certificate IPs
	CommonName  string                 // Certificate common name
	Status      JobStatus              // pending, processing, completed, failed
	CreatedAt   time.Time              // Job creation time
	UpdatedAt   time.Time              // Last update time
	CompletedAt *time.Time             // Completion timestamp
	Result      *IssuedCertificate     // Certificate result
	Error       string                 // Error message if failed
	PrivateKey  string                 // Stored PEM format (sensitive)
	CSR         string                 // Certificate Signing Request PEM
	Metadata    map[string]string      // Additional metadata
}

// IssuedCertificate represents the result of a successful certificate issuance
type IssuedCertificate struct {
	Certificate   string    // Certificate PEM
	CACertificate string    // CA Certificate PEM (chain)
	PrivateKey    string    // Private Key PEM
	SerialNumber  string    // Certificate serial number
	ExpiresAt     time.Time // Expiration time
	IssuedAt      time.Time // Issue time

	// Subject fields for certificate matching
	SubjectOrganization string // Certificate Subject Organization
	SubjectOrgUnit      string // Certificate Subject Organizational Unit
	SubjectCountry      string // Certificate Subject Country
}

// CertificateRequest represents a request to issue a certificate
type CertificateRequest struct {
	TenantID    uint32
	ClientID    string
	IssuerName  string
	IssuerType  string
	DNSNames    []string
	IPAddresses []string
	CommonName  string
	KeyType     string // ecdsa or rsa
	KeySize     int    // Key size in bits
	ValidityDays int   // Certificate validity in days
}

// CertificateJobManager manages async certificate signing jobs
type CertificateJobManager struct {
	jobs sync.Map // map[string]*CertificateJob - thread-safe storage
	log  *log.Helper
}

// NewCertificateJobManager creates a new job manager
func NewCertificateJobManager(logger log.Logger) *CertificateJobManager {
	return &CertificateJobManager{
		log: log.NewHelper(log.With(logger, "module", "lcm/job-manager")),
	}
}

// CreateJob creates a new certificate signing job
func (m *CertificateJobManager) CreateJob(req *CertificateRequest, privateKeyPEM, csrPEM string) *CertificateJob {
	now := time.Now()
	job := &CertificateJob{
		ID:          uuid.New().String(),
		TenantID:    req.TenantID,
		ClientID:    req.ClientID,
		IssuerName:  req.IssuerName,
		IssuerType:  req.IssuerType,
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddresses,
		CommonName:  req.CommonName,
		Status:      JobStatusPending,
		CreatedAt:   now,
		UpdatedAt:   now,
		PrivateKey:  privateKeyPEM,
		CSR:         csrPEM,
		Metadata:    make(map[string]string),
	}

	m.jobs.Store(job.ID, job)
	m.log.Infof("Created certificate job: id=%s, tenant=%d, client=%s, issuer=%s",
		job.ID, job.TenantID, job.ClientID, job.IssuerName)

	return job
}

// GetJob retrieves a job by ID
func (m *CertificateJobManager) GetJob(jobID string) (*CertificateJob, bool) {
	value, exists := m.jobs.Load(jobID)
	if !exists {
		return nil, false
	}
	return value.(*CertificateJob), true
}

// GetJobByTenant retrieves a job by ID and verifies tenant ownership
func (m *CertificateJobManager) GetJobByTenant(jobID string, tenantID uint32) (*CertificateJob, bool) {
	job, exists := m.GetJob(jobID)
	if !exists {
		return nil, false
	}
	if job.TenantID != tenantID {
		return nil, false
	}
	return job, true
}

// UpdateJobStatus updates the status of a job
func (m *CertificateJobManager) UpdateJobStatus(jobID string, status JobStatus) bool {
	value, exists := m.jobs.Load(jobID)
	if !exists {
		return false
	}

	job := value.(*CertificateJob)
	job.Status = status
	job.UpdatedAt = time.Now()
	m.jobs.Store(jobID, job)

	m.log.Infof("Updated job status: id=%s, status=%s", jobID, status)
	return true
}

// CompleteJob marks a job as completed with result or error
func (m *CertificateJobManager) CompleteJob(jobID string, result *IssuedCertificate, err error) bool {
	value, exists := m.jobs.Load(jobID)
	if !exists {
		return false
	}

	job := value.(*CertificateJob)
	now := time.Now()
	job.CompletedAt = &now
	job.UpdatedAt = now

	if err != nil {
		job.Status = JobStatusFailed
		job.Error = err.Error()
		m.log.Errorf("Job failed: id=%s, error=%v", jobID, err)
	} else {
		job.Status = JobStatusCompleted
		job.Result = result
		m.log.Infof("Job completed: id=%s, serial=%s", jobID, result.SerialNumber)
	}

	m.jobs.Store(jobID, job)
	return true
}

// ListJobsByTenant returns all jobs for a tenant
func (m *CertificateJobManager) ListJobsByTenant(tenantID uint32) []*CertificateJob {
	var jobs []*CertificateJob
	m.jobs.Range(func(key, value interface{}) bool {
		job := value.(*CertificateJob)
		if job.TenantID == tenantID {
			jobs = append(jobs, job)
		}
		return true
	})
	return jobs
}

// ListAllJobs returns all jobs across all tenants (admin only)
func (m *CertificateJobManager) ListAllJobs() []*CertificateJob {
	var jobs []*CertificateJob
	m.jobs.Range(func(key, value interface{}) bool {
		job := value.(*CertificateJob)
		jobs = append(jobs, job)
		return true
	})
	return jobs
}

// ListJobsByClient returns all jobs for a specific client
func (m *CertificateJobManager) ListJobsByClient(tenantID uint32, clientID string) []*CertificateJob {
	var jobs []*CertificateJob
	m.jobs.Range(func(key, value interface{}) bool {
		job := value.(*CertificateJob)
		if job.TenantID == tenantID && job.ClientID == clientID {
			jobs = append(jobs, job)
		}
		return true
	})
	return jobs
}

// CleanupOldJobs removes jobs older than the specified duration
func (m *CertificateJobManager) CleanupOldJobs(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	m.jobs.Range(func(key, value interface{}) bool {
		job := value.(*CertificateJob)
		// Only clean up completed or failed jobs
		if (job.Status == JobStatusCompleted || job.Status == JobStatusFailed) &&
			job.CompletedAt != nil && job.CompletedAt.Before(cutoff) {
			m.jobs.Delete(key)
			removed++
			m.log.Debugf("Cleaned up old job: id=%s, completed_at=%s", job.ID, job.CompletedAt)
		}
		return true
	})

	if removed > 0 {
		m.log.Infof("Cleaned up %d old certificate jobs", removed)
	}
	return removed
}

// StartCleanupRoutine starts a background goroutine to clean up old jobs
func (m *CertificateJobManager) StartCleanupRoutine(interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			m.CleanupOldJobs(maxAge)
		}
	}()
	m.log.Infof("Started job cleanup routine: interval=%s, maxAge=%s", interval, maxAge)
}

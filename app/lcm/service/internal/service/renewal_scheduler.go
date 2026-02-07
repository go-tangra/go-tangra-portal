package service

import (
	"context"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/biz"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/certificaterenewal"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/event"
)

// RenewalScheduler handles automatic certificate renewal
type RenewalScheduler struct {
	log                   *log.Helper
	config                *conf.RenewalConfig
	issuedCertRepo        *data.IssuedCertificateRepo
	renewalRepo           *data.CertificateRenewalRepo
	issuerRepo            *data.IssuerRepo
	clientRepo            *data.LcmClientRepo
	certificateJobService *CertificateJobService
	eventPublisher        *event.Publisher

	workerID    string
	stopCh      chan struct{}
	wg          sync.WaitGroup
	running     bool
	runningLock sync.Mutex
}

// NewRenewalScheduler creates a new RenewalScheduler
func NewRenewalScheduler(
	ctx *bootstrap.Context,
	config *conf.RenewalConfig,
	issuedCertRepo *data.IssuedCertificateRepo,
	renewalRepo *data.CertificateRenewalRepo,
	issuerRepo *data.IssuerRepo,
	clientRepo *data.LcmClientRepo,
	certificateJobService *CertificateJobService,
	eventPublisher *event.Publisher,
) *RenewalScheduler {
	return &RenewalScheduler{
		log:                   ctx.NewLoggerHelper("lcm/service/renewal-scheduler"),
		config:                config,
		issuedCertRepo:        issuedCertRepo,
		renewalRepo:           renewalRepo,
		issuerRepo:            issuerRepo,
		clientRepo:            clientRepo,
		certificateJobService: certificateJobService,
		eventPublisher:        eventPublisher,
		workerID:              data.GenerateWorkerID(),
	}
}

// Start starts the renewal scheduler
func (s *RenewalScheduler) Start() error {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if s.running {
		return nil
	}

	if s.config == nil || !s.config.GetEnabled() {
		s.log.Info("Renewal scheduler is disabled")
		return nil
	}

	s.stopCh = make(chan struct{})
	s.running = true

	// Get configuration values with defaults
	checkInterval := time.Duration(s.config.GetCheckIntervalSeconds()) * time.Second
	if checkInterval <= 0 {
		checkInterval = time.Hour
	}

	workerCount := int(s.config.GetWorkerCount())
	if workerCount <= 0 {
		workerCount = 2
	}

	s.log.Infof("Starting renewal scheduler: check_interval=%s, workers=%d, worker_id=%s",
		checkInterval, workerCount, s.workerID)

	// Start the scanner goroutine
	s.wg.Add(1)
	go s.runScanner(checkInterval)

	// Start worker goroutines
	for i := 0; i < workerCount; i++ {
		s.wg.Add(1)
		go s.runWorker(i)
	}

	// Start cleanup goroutine
	s.wg.Add(1)
	go s.runCleanup()

	return nil
}

// Stop stops the renewal scheduler
func (s *RenewalScheduler) Stop() error {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if !s.running {
		return nil
	}

	s.log.Info("Stopping renewal scheduler...")
	close(s.stopCh)
	s.wg.Wait()
	s.running = false
	s.log.Info("Renewal scheduler stopped")

	return nil
}

// runScanner periodically scans for certificates due for renewal
func (s *RenewalScheduler) runScanner(interval time.Duration) {
	defer s.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on start
	s.scanAndScheduleRenewals()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.scanAndScheduleRenewals()
		}
	}
}

// scanAndScheduleRenewals scans for certificates due for renewal and creates renewal jobs
func (s *RenewalScheduler) scanAndScheduleRenewals() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	s.log.Debug("Scanning for certificates due for renewal...")

	// Get default configuration values
	daysBeforeExpiry := s.config.GetDefaultDaysBeforeExpiry()
	if daysBeforeExpiry <= 0 {
		daysBeforeExpiry = 30
	}

	batchSize := int(s.config.GetBatchSize())
	if batchSize <= 0 {
		batchSize = 100
	}

	// Find certificates due for renewal
	certs, err := s.issuedCertRepo.FindCertificatesDueForRenewal(ctx, daysBeforeExpiry, batchSize)
	if err != nil {
		s.log.Errorf("Failed to find certificates for renewal: %v", err)
		return
	}

	if len(certs) == 0 {
		s.log.Debug("No certificates due for renewal")
		return
	}

	s.log.Infof("Found %d certificates due for renewal", len(certs))

	scheduled := 0
	for _, cert := range certs {
		// Check if there's already a pending renewal
		existing, err := s.renewalRepo.GetPendingByCertificateID(ctx, cert.ID)
		if err != nil {
			s.log.Errorf("Failed to check existing renewal for cert %s: %v", cert.ID, err)
			continue
		}
		if existing != nil {
			s.log.Debugf("Renewal already pending for cert %s", cert.ID)
			continue
		}

		// Get max attempts from cert or config
		maxAttempts := cert.AutoRenewMaxAttempts
		if maxAttempts <= 0 {
			maxAttempts = s.config.GetRetryMaxAttempts()
		}
		if maxAttempts <= 0 {
			maxAttempts = 3
		}

		// Create renewal job
		renewal := &ent.CertificateRenewal{
			CertificateID:     cert.ID,
			ClientID:          cert.ClientID,
			IssuerName:        cert.IssuerName,
			Domains:           cert.Domains,
			OriginalExpiresAt: cert.ExpiresAt,
			ScheduledAt:       time.Now(),
			MaxAttempts:       maxAttempts,
		}

		createdRenewal, err := s.renewalRepo.Create(ctx, renewal)
		if err != nil {
			s.log.Errorf("Failed to create renewal job for cert %s: %v", cert.ID, err)
			continue
		}

		scheduled++
		s.log.Infof("Scheduled renewal for certificate %s (expires: %s)", cert.ID, cert.ExpiresAt)

		// Publish renewal scheduled event
		if s.eventPublisher != nil && createdRenewal != nil {
			var tenantID uint32 = 0
			if cert.Edges.LcmClient != nil && cert.Edges.LcmClient.TenantID != nil {
				tenantID = *cert.Edges.LcmClient.TenantID
			}
			_ = s.eventPublisher.PublishRenewalScheduled(ctx, &event.RenewalScheduledEvent{
				RenewalID:     createdRenewal.ID,
				CertificateID: cert.ID,
				ClientID:      cert.ClientID,
				TenantID:      tenantID,
				IssuerName:    cert.IssuerName,
				ScheduledAt:   createdRenewal.ScheduledAt,
				ExpiresAt:     cert.ExpiresAt,
			})
		}
	}

	if scheduled > 0 {
		s.log.Infof("Scheduled %d renewal jobs", scheduled)
	}
}

// runWorker processes renewal jobs
func (s *RenewalScheduler) runWorker(workerNum int) {
	defer s.wg.Done()

	workerID := s.workerID + "-" + string(rune('0'+workerNum))
	s.log.Infof("Renewal worker %d started (id: %s)", workerNum, workerID)

	// Poll interval for workers
	pollInterval := 30 * time.Second

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			s.log.Infof("Renewal worker %d stopping", workerNum)
			return
		case <-ticker.C:
			s.processNextRenewal(workerID)
		}
	}
}

// processNextRenewal attempts to process the next pending renewal
func (s *RenewalScheduler) processNextRenewal(workerID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Find pending renewals
	renewals, err := s.renewalRepo.FindPendingRenewals(ctx, 1)
	if err != nil {
		s.log.Errorf("Failed to find pending renewals: %v", err)
		return
	}

	if len(renewals) == 0 {
		return
	}

	renewal := renewals[0]

	// Get lock timeout from config
	lockTimeout := time.Duration(s.config.GetLockTimeoutSeconds()) * time.Second
	if lockTimeout <= 0 {
		lockTimeout = 5 * time.Minute
	}

	// Try to acquire lock
	acquired, err := s.renewalRepo.TryLock(ctx, renewal.ID, workerID, lockTimeout)
	if err != nil {
		s.log.Errorf("Failed to acquire lock for renewal %d: %v", renewal.ID, err)
		return
	}
	if !acquired {
		return // Another worker got it
	}

	s.log.Infof("Worker %s processing renewal %d for certificate %s", workerID, renewal.ID, renewal.CertificateID)

	// Process the renewal
	err = s.processRenewal(ctx, renewal)
	if err != nil {
		s.handleRenewalFailure(ctx, renewal, err)
	} else {
		s.handleRenewalSuccess(ctx, renewal)
	}
}

// processRenewal processes a single renewal job
func (s *RenewalScheduler) processRenewal(ctx context.Context, renewal *ent.CertificateRenewal) error {
	// Get the original certificate
	cert, err := s.issuedCertRepo.GetByID(ctx, renewal.CertificateID)
	if err != nil {
		return err
	}
	if cert == nil {
		return &renewalError{message: "certificate not found", permanent: true}
	}

	// Get the client's tenant ID
	var tenantID uint32 = 0
	if cert.Edges.LcmClient != nil && cert.Edges.LcmClient.TenantID != nil {
		tenantID = *cert.Edges.LcmClient.TenantID
	}

	// Get the issuer
	issuerEntity, err := s.issuerRepo.GetByTenantAndName(ctx, tenantID, renewal.IssuerName)
	if err != nil {
		return err
	}
	if issuerEntity == nil {
		return &renewalError{message: "issuer not found", permanent: true}
	}

	// Get common name from domains
	commonName := getCommonNameFromDomains(renewal.Domains)

	// Generate new key and CSR for renewal
	keyType := "ecdsa"
	keySize := 256
	if cert.KeyType != "" {
		keyType = string(cert.KeyType)
	}
	if cert.KeySize > 0 {
		keySize = int(cert.KeySize)
	}

	privateKeyPEM, csrPEM, err := generateKeyAndCSR(commonName, renewal.Domains, nil, keyType, keySize)
	if err != nil {
		return &renewalError{message: "failed to generate key/CSR: " + err.Error(), permanent: false}
	}

	// Create certificate request for the service methods
	certReq := &biz.CertificateRequest{
		TenantID:   tenantID,
		ClientID:   renewal.ClientID,
		IssuerName: renewal.IssuerName,
		IssuerType: string(issuerEntity.Type),
		DNSNames:   renewal.Domains,
		CommonName: commonName,
	}

	// Issue the new certificate synchronously
	s.log.Infof("Issuing renewed certificate for %s", renewal.CertificateID)

	var issuedCert *biz.IssuedCertificate

	switch issuerEntity.Type.String() {
	case "self-signed":
		issuedCert, err = s.certificateJobService.issueSelfSignedCertificate(ctx, issuerEntity, certReq, csrPEM)
	case "acme":
		issuedCert, err = s.certificateJobService.issueACMECertificate(ctx, issuerEntity, certReq, csrPEM, privateKeyPEM)
	default:
		return &renewalError{message: "unsupported issuer type: " + issuerEntity.Type.String(), permanent: true}
	}

	if err != nil {
		return &renewalError{message: "failed to issue certificate: " + err.Error(), permanent: false}
	}

	// Update the issued certificate with new data
	err = s.issuedCertRepo.UpdateCertificate(ctx, cert.ID, issuedCert.Certificate, privateKeyPEM, issuedCert.CACertificate, "", issuedCert.ExpiresAt)
	if err != nil {
		return &renewalError{message: "failed to update certificate: " + err.Error(), permanent: false}
	}

	// Reset renewal attempts
	err = s.issuedCertRepo.ResetRenewalAttempts(ctx, cert.ID)
	if err != nil {
		s.log.Warnf("Failed to reset renewal attempts for cert %s: %v", cert.ID, err)
	}

	return nil
}

// handleRenewalSuccess handles successful certificate renewal
func (s *RenewalScheduler) handleRenewalSuccess(ctx context.Context, renewal *ent.CertificateRenewal) {
	err := s.renewalRepo.MarkCompleted(ctx, renewal.ID)
	if err != nil {
		s.log.Errorf("Failed to mark renewal %d as completed: %v", renewal.ID, err)
	}
	s.log.Infof("Certificate renewal completed successfully: cert=%s, renewal=%d", renewal.CertificateID, renewal.ID)

	// Get updated certificate for event data
	cert, _ := s.issuedCertRepo.GetByID(ctx, renewal.CertificateID)

	// Publish renewal completed event
	if s.eventPublisher != nil {
		var tenantID uint32 = 0
		var newSerial string
		var newExpiresAt time.Time
		if cert != nil {
			if cert.Edges.LcmClient != nil && cert.Edges.LcmClient.TenantID != nil {
				tenantID = *cert.Edges.LcmClient.TenantID
			}
			// Get serial number from certificate details
			if cert.Edges.CertificateDetails != nil {
				newSerial = cert.Edges.CertificateDetails.SerialNumber
			}
			newExpiresAt = cert.ExpiresAt
		}
		_ = s.eventPublisher.PublishRenewalCompleted(ctx, &event.RenewalCompletedEvent{
			RenewalID:       renewal.ID,
			CertificateID:   renewal.CertificateID,
			ClientID:        renewal.ClientID,
			TenantID:        tenantID,
			NewSerialNumber: newSerial,
			NewExpiresAt:    newExpiresAt,
			AttemptNumber:   renewal.AttemptNumber,
		})
	}
}

// handleRenewalFailure handles failed certificate renewal
func (s *RenewalScheduler) handleRenewalFailure(ctx context.Context, renewal *ent.CertificateRenewal, renewalErr error) {
	s.log.Errorf("Certificate renewal failed: cert=%s, renewal=%d, error=%v", renewal.CertificateID, renewal.ID, renewalErr)

	// Increment attempts on the certificate
	_ = s.issuedCertRepo.IncrementRenewalAttempts(ctx, renewal.CertificateID)

	// Check if this is a permanent error or we've exceeded max attempts
	permanent := false
	if re, ok := renewalErr.(*renewalError); ok {
		permanent = re.permanent
	}

	willRetry := !permanent && renewal.AttemptNumber < renewal.MaxAttempts

	// Get tenant ID for event
	var tenantID uint32 = 0
	cert, _ := s.issuedCertRepo.GetByID(ctx, renewal.CertificateID)
	if cert != nil && cert.Edges.LcmClient != nil && cert.Edges.LcmClient.TenantID != nil {
		tenantID = *cert.Edges.LcmClient.TenantID
	}

	// Publish failure event
	if s.eventPublisher != nil {
		_ = s.eventPublisher.PublishRenewalFailed(ctx, &event.RenewalFailedEvent{
			RenewalID:     renewal.ID,
			CertificateID: renewal.CertificateID,
			ClientID:      renewal.ClientID,
			TenantID:      tenantID,
			ErrorMessage:  renewalErr.Error(),
			AttemptNumber: renewal.AttemptNumber,
			MaxAttempts:   renewal.MaxAttempts,
			WillRetry:     willRetry,
		})
	}

	if !willRetry {
		// Mark as permanently failed
		err := s.renewalRepo.MarkFailed(ctx, renewal.ID, renewalErr.Error())
		if err != nil {
			s.log.Errorf("Failed to mark renewal %d as failed: %v", renewal.ID, err)
		}
		s.log.Warnf("Certificate renewal permanently failed after %d attempts: cert=%s", renewal.AttemptNumber, renewal.CertificateID)
		return
	}

	// Schedule retry
	retryInterval := time.Duration(s.config.GetRetryIntervalSeconds()) * time.Second
	if retryInterval <= 0 {
		retryInterval = time.Hour
	}

	retryAt := time.Now().Add(retryInterval)
	err := s.renewalRepo.ScheduleRetry(ctx, renewal.ID, retryAt, renewalErr.Error())
	if err != nil {
		s.log.Errorf("Failed to schedule retry for renewal %d: %v", renewal.ID, err)
	}
	s.log.Infof("Scheduled renewal retry for cert %s at %s (attempt %d)", renewal.CertificateID, retryAt, renewal.AttemptNumber+1)
}

// runCleanup periodically cleans up expired locks
func (s *RenewalScheduler) runCleanup() {
	defer s.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			cleaned, err := s.renewalRepo.CleanupExpiredLocks(ctx)
			if err != nil {
				s.log.Errorf("Failed to cleanup expired locks: %v", err)
			} else if cleaned > 0 {
				s.log.Infof("Cleaned up %d expired renewal locks", cleaned)
			}
			cancel()
		}
	}
}

// renewalError represents a renewal-specific error
type renewalError struct {
	message   string
	permanent bool
}

func (e *renewalError) Error() string {
	return e.message
}

// getCommonNameFromDomains extracts common name from domains list
func getCommonNameFromDomains(domains []string) string {
	if len(domains) > 0 {
		return domains[0]
	}
	return ""
}

// ManualRenewal triggers a manual renewal for a specific certificate
func (s *RenewalScheduler) ManualRenewal(ctx context.Context, certificateID string) error {
	// Get the certificate
	cert, err := s.issuedCertRepo.GetByID(ctx, certificateID)
	if err != nil {
		return err
	}
	if cert == nil {
		return &renewalError{message: "certificate not found", permanent: true}
	}

	// Check if there's already a pending renewal
	existing, err := s.renewalRepo.GetPendingByCertificateID(ctx, certificateID)
	if err != nil {
		return err
	}
	if existing != nil && existing.Status == certificaterenewal.StatusProcessing {
		return &renewalError{message: "renewal already in progress", permanent: false}
	}

	// Cancel any existing pending renewal
	if existing != nil {
		_ = s.renewalRepo.Cancel(ctx, existing.ID)
	}

	// Create a new renewal job scheduled immediately
	renewal := &ent.CertificateRenewal{
		CertificateID:     cert.ID,
		ClientID:          cert.ClientID,
		IssuerName:        cert.IssuerName,
		Domains:           cert.Domains,
		OriginalExpiresAt: cert.ExpiresAt,
		ScheduledAt:       time.Now(),
		MaxAttempts:       3,
	}

	_, err = s.renewalRepo.Create(ctx, renewal)
	if err != nil {
		return err
	}

	s.log.Infof("Manual renewal scheduled for certificate %s", certificateID)
	return nil
}

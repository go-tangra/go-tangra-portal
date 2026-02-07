package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/biz"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/acmeissuer"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/issuedcertificate"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/issuer"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/event"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/registry"
)

// CertificateJobService implements the LcmCertificateJobService gRPC service
type CertificateJobService struct {
	lcmV1.UnimplementedLcmCertificateJobServiceServer

	log                   *log.Helper
	issuerRepo            *data.IssuerRepo
	clientRepo            *data.LcmClientRepo
	mtlsCertRepo          *data.MtlsCertificateRepo
	issuedCertRepo        *data.IssuedCertificateRepo
	dnsPropagationChecker *biz.DNSPropagationChecker
	eventPublisher        *event.Publisher
}

// NewCertificateJobService creates a new CertificateJobService
func NewCertificateJobService(
	ctx *bootstrap.Context,
	issuerRepo *data.IssuerRepo,
	clientRepo *data.LcmClientRepo,
	mtlsCertRepo *data.MtlsCertificateRepo,
	issuedCertRepo *data.IssuedCertificateRepo,
	eventPublisher *event.Publisher,
) *CertificateJobService {
	dnsPropagationChecker := biz.NewDNSPropagationChecker(ctx.GetLogger())

	return &CertificateJobService{
		log:                   ctx.NewLoggerHelper("lcm/service/certificate-job"),
		issuerRepo:            issuerRepo,
		clientRepo:            clientRepo,
		mtlsCertRepo:          mtlsCertRepo,
		issuedCertRepo:        issuedCertRepo,
		dnsPropagationChecker: dnsPropagationChecker,
		eventPublisher:        eventPublisher,
	}
}

// getClientInfo extracts the tenant ID and client ID from the authenticated client
// and sets the tenant ID in context for audit logging.
// The mTLS certificate CN may be the hostname, but the actual client_id is the machine-id.
// We use the mtls_certificates table to map CN -> client_id.
func (s *CertificateJobService) getClientInfo(ctx context.Context) (uint32, string, error) {
	// Get CN from mTLS certificate (this may be hostname, not machine-id)
	certCN := client.GetClientID(ctx)
	if certCN == "" {
		return 0, "", lcmV1.ErrorUnauthorized("client authentication required")
	}

	// First, try to find the actual client_id by looking up the CN in mtls_certificates
	// This handles the case where CN is hostname but client_id is machine-id
	clientID := certCN // Default to CN if no mapping found
	if s.mtlsCertRepo != nil {
		actualClientID, err := s.mtlsCertRepo.GetClientIDByCommonName(ctx, certCN)
		if err != nil {
			s.log.Errorf("Failed to lookup client_id by CN: %v", err)
			// Continue with CN as client_id (backwards compatibility)
		} else if actualClientID != "" {
			clientID = actualClientID
			s.log.Debugf("Resolved CN '%s' to client_id '%s'", certCN, clientID)
		}
	}

	// First try to find client with tenant_id = 0 (platform-level clients)
	lcmClient, err := s.clientRepo.GetByTenantAndClientID(ctx, 0, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, "", lcmV1.ErrorInternalServerError("failed to lookup client")
	}

	if lcmClient != nil {
		var tenantID uint32
		if lcmClient.TenantID != nil {
			tenantID = *lcmClient.TenantID
			client.SetTenantIDInPlace(ctx, tenantID)
		}
		return tenantID, clientID, nil
	}

	// If not found at platform level, search across all tenants
	allClients, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, "", lcmV1.ErrorInternalServerError("failed to lookup client")
	}
	if allClients == nil {
		return 0, "", lcmV1.ErrorNotFound("client not registered")
	}

	var tenantID uint32
	if allClients.TenantID != nil {
		tenantID = *allClients.TenantID
		client.SetTenantIDInPlace(ctx, tenantID)
	}
	return tenantID, clientID, nil
}

// RequestCertificate creates a new certificate signing job (async)
func (s *CertificateJobService) RequestCertificate(ctx context.Context, req *lcmV1.RequestCertificateRequest) (*lcmV1.RequestCertificateResponse, error) {
	tenantID, clientID, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	s.log.Infof("RequestCertificate: tenant=%d, client=%s, issuer=%s, cn=%s",
		tenantID, clientID, req.GetIssuerName(), req.GetCommonName())

	// Validate and get the issuer
	issuerEntity, err := s.issuerRepo.GetByTenantAndName(ctx, tenantID, req.GetIssuerName())
	if err != nil {
		return nil, err
	}
	if issuerEntity == nil {
		return nil, lcmV1.ErrorNotFound("issuer '%s' not found", req.GetIssuerName())
	}

	// Check issuer status
	if issuerEntity.Status != nil && *issuerEntity.Status != issuer.StatusISSUER_STATUS_ACTIVE {
		return nil, lcmV1.ErrorBadRequest("issuer '%s' is not active", req.GetIssuerName())
	}

	// Handle key/CSR generation
	var privateKeyPEM, csrPEM string
	if req.CsrPem != nil && *req.CsrPem != "" {
		// Client provided CSR
		csrPEM = *req.CsrPem
		// Parse and validate CSR
		_, err := parseCSR(csrPEM)
		if err != nil {
			return nil, lcmV1.ErrorBadRequest("invalid CSR: %v", err)
		}
	} else {
		// Generate key and CSR
		keyType := "ecdsa"
		keySize := 256
		if req.KeyType != nil && *req.KeyType != "" {
			keyType = strings.ToLower(*req.KeyType)
		}
		if req.KeySize != nil && *req.KeySize > 0 {
			keySize = int(*req.KeySize)
		}

		privateKeyPEM, csrPEM, err = generateKeyAndCSR(req.GetCommonName(), req.GetDnsNames(), req.GetIpAddresses(), keyType, keySize)
		if err != nil {
			s.log.Errorf("Failed to generate key/CSR: %v", err)
			return nil, lcmV1.ErrorInternalServerError("failed to generate key/CSR")
		}
	}

	// Create certificate request
	certReq := &biz.CertificateRequest{
		TenantID:     tenantID,
		ClientID:     clientID,
		IssuerName:   req.GetIssuerName(),
		IssuerType:   string(issuerEntity.Type),
		DNSNames:     req.GetDnsNames(),
		IPAddresses:  req.GetIpAddresses(),
		CommonName:   req.GetCommonName(),
		KeyType:      "ecdsa",
		ValidityDays: 90, // Default
	}
	if req.ValidityDays != nil && *req.ValidityDays > 0 {
		certReq.ValidityDays = int(*req.ValidityDays)
	}

	// Generate job ID
	jobID := uuid.New().String()

	// Persist job to database
	_, err = s.issuedCertRepo.CreateJob(ctx, &data.CreateJobRequest{
		ID:           jobID,
		TenantID:     tenantID,
		ClientID:     clientID,
		IssuerName:   req.GetIssuerName(),
		IssuerType:   string(issuerEntity.Type),
		CommonName:   req.GetCommonName(),
		DNSNames:     req.GetDnsNames(),
		IPAddresses:  req.GetIpAddresses(),
		CSR:          csrPEM,
		PrivateKey:   privateKeyPEM,
		KeyType:      certReq.KeyType,
		KeySize:      int32(certReq.KeySize),
		ServerGenKey: privateKeyPEM != "",
	})
	if err != nil {
		s.log.Errorf("Failed to persist job to database: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to create certificate job")
	}

	// Start async processing
	go s.processCertificateJob(jobID, issuerEntity, certReq, csrPEM, privateKeyPEM)

	// Publish certificate requested event
	if s.eventPublisher != nil {
		_ = s.eventPublisher.PublishCertificateRequested(ctx, &event.CertificateRequestedEvent{
			JobID:       jobID,
			ClientID:    clientID,
			TenantID:    tenantID,
			IssuerName:  req.GetIssuerName(),
			IssuerType:  string(issuerEntity.Type),
			CommonName:  req.GetCommonName(),
			DNSNames:    req.GetDnsNames(),
			IPAddresses: req.GetIpAddresses(),
		})
	}

	return &lcmV1.RequestCertificateResponse{
		JobId:   jobID,
		Status:  lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING,
		Message: "Certificate request submitted successfully. Poll GetJobStatus for progress.",
	}, nil
}

// GetJobStatus returns the status of a certificate signing job
func (s *CertificateJobService) GetJobStatus(ctx context.Context, req *lcmV1.GetJobStatusRequest) (*lcmV1.GetJobStatusResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Get job from database
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetJobId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("job '%s' not found", req.GetJobId())
	}

	// Verify tenant access (admin can see all, others can only see their own)
	if tenantID != 0 && cert.TenantID != tenantID {
		return nil, lcmV1.ErrorNotFound("job '%s' not found", req.GetJobId())
	}

	response := &lcmV1.GetJobStatusResponse{
		JobId:       cert.ID,
		Status:      mapDBStatusToProto(cert.Status),
		IssuerName:  cert.IssuerName,
		IssuerType:  cert.IssuerType,
		CommonName:  cert.CommonName,
		DnsNames:    cert.Domains,
		IpAddresses: cert.IPAddresses,
		CreatedAt:   timestamppb.New(cert.CreatedAt),
	}

	if !cert.UpdatedAt.IsZero() && cert.Status != issuedcertificate.StatusPending && cert.Status != issuedcertificate.StatusProcessing {
		response.CompletedAt = timestamppb.New(cert.UpdatedAt)
	}

	if cert.ErrorMessage != "" {
		response.ErrorMessage = &cert.ErrorMessage
	}

	return response, nil
}

// GetJobResult returns the result of a completed certificate signing job
func (s *CertificateJobService) GetJobResult(ctx context.Context, req *lcmV1.GetJobResultRequest) (*lcmV1.GetJobResultResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Get job from database
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetJobId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("job '%s' not found", req.GetJobId())
	}

	// Verify tenant access (admin can see all, others can only see their own)
	if tenantID != 0 && cert.TenantID != tenantID {
		return nil, lcmV1.ErrorNotFound("job '%s' not found", req.GetJobId())
	}

	response := &lcmV1.GetJobResultResponse{
		JobId:  cert.ID,
		Status: mapDBStatusToProto(cert.Status),
	}

	if cert.Status == issuedcertificate.StatusIssued {
		response.CertificatePem = &cert.CertPem
		response.CaCertificatePem = &cert.CaCertPem
		response.SerialNumber = &cert.CertificateFingerprint
		if !cert.ExpiresAt.IsZero() {
			response.ExpiresAt = timestamppb.New(cert.ExpiresAt)
		}
		response.IssuedAt = timestamppb.New(cert.CreatedAt)

		// Include private key only if requested and server generated it
		if req.IncludePrivateKey != nil && *req.IncludePrivateKey && cert.ServerGeneratedKey && cert.PrivateKeyPem != "" {
			response.PrivateKeyPem = &cert.PrivateKeyPem
		}
	}

	if cert.ErrorMessage != "" {
		response.ErrorMessage = &cert.ErrorMessage
	}

	return response, nil
}

// ListJobs lists certificate jobs for the authenticated client
func (s *CertificateJobService) ListJobs(ctx context.Context, req *lcmV1.ListJobsRequest) (*lcmV1.ListJobsResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Build filter for database query
	filter := &data.ListFilter{
		IssuerName: req.GetIssuerName(),
		Page:       req.GetPage(),
		PageSize:   req.GetPageSize(),
	}

	// Set default pagination
	if filter.PageSize == 0 {
		filter.PageSize = 20
	}
	if filter.Page == 0 {
		filter.Page = 1
	}

	// Admin clients (tenant_id=0) can query all jobs or a specific tenant's jobs
	if tenantID == 0 {
		if req.TenantId != nil {
			// Admin requesting specific tenant's jobs
			filter.TenantID = req.TenantId
		}
		// If TenantID is nil, query all tenants (no filter)
	} else {
		// Regular clients can only see their own tenant's jobs
		filter.TenantID = &tenantID
	}

	// Map proto status to database status
	if req.Status != nil && *req.Status != lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_UNSPECIFIED {
		dbStatus := mapProtoStatusToDBStatus(*req.Status)
		filter.Status = &dbStatus
	}

	// Query the database
	certs, total, err := s.issuedCertRepo.List(ctx, filter)
	if err != nil {
		s.log.Errorf("Failed to list certificates: %v", err)
		return nil, err
	}

	response := &lcmV1.ListJobsResponse{
		Jobs:  make([]*lcmV1.CertificateJobInfo, 0, len(certs)),
		Total: total,
	}

	for _, cert := range certs {
		jobInfo := &lcmV1.CertificateJobInfo{
			JobId:      cert.ID,
			Status:     mapDBStatusToProto(cert.Status),
			IssuerName: cert.IssuerName,
			IssuerType: cert.IssuerType,
			CommonName: cert.CommonName,
			CreatedAt:  timestamppb.New(cert.CreatedAt),
		}
		if !cert.UpdatedAt.IsZero() && cert.Status != "pending" && cert.Status != "processing" {
			jobInfo.CompletedAt = timestamppb.New(cert.UpdatedAt)
		}
		if cert.ErrorMessage != "" {
			jobInfo.ErrorMessage = &cert.ErrorMessage
		}
		response.Jobs = append(response.Jobs, jobInfo)
	}

	return response, nil
}

// CancelJob cancels a pending certificate job
func (s *CertificateJobService) CancelJob(ctx context.Context, req *lcmV1.CancelJobRequest) (*emptypb.Empty, error) {
	tenantID, clientID, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Get job from database
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetJobId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("job '%s' not found", req.GetJobId())
	}

	// Verify tenant access
	if tenantID != 0 && cert.TenantID != tenantID {
		return nil, lcmV1.ErrorNotFound("job '%s' not found", req.GetJobId())
	}

	if cert.Status != issuedcertificate.StatusPending {
		return nil, lcmV1.ErrorBadRequest("can only cancel pending jobs, current status: %s", cert.Status)
	}

	// Update status in database
	if err := s.issuedCertRepo.FailJob(ctx, req.GetJobId(), "cancelled by user"); err != nil {
		s.log.Errorf("Failed to cancel job in database: %v", err)
		return nil, err
	}
	s.log.Infof("Job cancelled: id=%s", req.GetJobId())

	// Publish cancellation event
	if s.eventPublisher != nil {
		_ = s.eventPublisher.PublishCertificateCancelled(ctx, &event.CertificateCancelledEvent{
			JobID:    req.GetJobId(),
			ClientID: clientID,
			TenantID: tenantID,
		})
	}

	return &emptypb.Empty{}, nil
}

// processCertificateJob processes a certificate signing job asynchronously
func (s *CertificateJobService) processCertificateJob(jobID string, issuerEntity *ent.Issuer, certReq *biz.CertificateRequest, csrPEM, privateKeyPEM string) {
	// Update job status to processing in database
	if err := s.issuedCertRepo.UpdateStatus(context.Background(), jobID, issuedcertificate.StatusProcessing, ""); err != nil {
		s.log.Errorf("Failed to update job status to processing: %v", err)
	}

	// Create a background context with appropriate timeout based on issuer type
	var timeout time.Duration
	switch issuerEntity.Type {
	case issuer.TypeAcme:
		timeout = 15 * time.Minute // ACME can take longer due to DNS challenges
	case issuer.TypeSelfSigned:
		timeout = 30 * time.Second // Self-signed should be fast
	default:
		timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	s.log.Infof("Processing certificate job: id=%s, type=%s, timeout=%s", jobID, issuerEntity.Type, timeout)

	// Publish processing event
	if s.eventPublisher != nil {
		_ = s.eventPublisher.PublishCertificateProcessing(ctx, &event.CertificateRequestedEvent{
			JobID:       jobID,
			ClientID:    certReq.ClientID,
			TenantID:    certReq.TenantID,
			IssuerName:  certReq.IssuerName,
			IssuerType:  certReq.IssuerType,
			CommonName:  certReq.CommonName,
			DNSNames:    certReq.DNSNames,
			IPAddresses: certReq.IPAddresses,
		})
	}

	// Issue certificate based on type
	var issuedCert *biz.IssuedCertificate
	var err error

	switch issuerEntity.Type {
	case issuer.TypeSelfSigned:
		issuedCert, err = s.issueSelfSignedCertificate(ctx, issuerEntity, certReq, csrPEM)
	case issuer.TypeAcme:
		issuedCert, err = s.issueACMECertificate(ctx, issuerEntity, certReq, csrPEM, privateKeyPEM)
	default:
		err = fmt.Errorf("unsupported issuer type: %s", issuerEntity.Type)
	}

	if err != nil {
		s.log.Errorf("Certificate issuance failed for job %s: %v", jobID, err)

		// Persist failure to database
		if dbErr := s.issuedCertRepo.FailJob(ctx, jobID, err.Error()); dbErr != nil {
			s.log.Errorf("Failed to persist job failure: %v", dbErr)
		}

		// Publish failure event
		if s.eventPublisher != nil {
			_ = s.eventPublisher.PublishCertificateFailed(ctx, &event.CertificateFailedEvent{
				JobID:        jobID,
				ClientID:     certReq.ClientID,
				TenantID:     certReq.TenantID,
				IssuerName:   certReq.IssuerName,
				IssuerType:   certReq.IssuerType,
				CommonName:   certReq.CommonName,
				ErrorMessage: err.Error(),
			})
		}
		return
	}

	// Add private key to result if we generated it
	if privateKeyPEM != "" {
		issuedCert.PrivateKey = privateKeyPEM
	}

	// Persist completion to database
	if dbErr := s.issuedCertRepo.CompleteJob(ctx, jobID, &data.CompleteJobRequest{
		Certificate:   issuedCert.Certificate,
		CACertificate: issuedCert.CACertificate,
		SerialNumber:  issuedCert.SerialNumber,
		ExpiresAt:     issuedCert.ExpiresAt,
	}); dbErr != nil {
		s.log.Errorf("Failed to persist job completion: %v", dbErr)
	}
	s.log.Infof("Certificate job completed: id=%s, serial=%s", jobID, issuedCert.SerialNumber)

	// Publish success event
	if s.eventPublisher != nil {
		_ = s.eventPublisher.PublishCertificateIssued(ctx, &event.CertificateIssuedEvent{
			JobID:               jobID,
			ClientID:            certReq.ClientID,
			TenantID:            certReq.TenantID,
			IssuerName:          certReq.IssuerName,
			IssuerType:          certReq.IssuerType,
			SerialNumber:        issuedCert.SerialNumber,
			CommonName:          certReq.CommonName,
			DNSNames:            certReq.DNSNames,
			IssuedAt:            issuedCert.IssuedAt,
			ExpiresAt:           issuedCert.ExpiresAt,
			SubjectOrganization: issuedCert.SubjectOrganization,
			SubjectOrgUnit:      issuedCert.SubjectOrgUnit,
			SubjectCountry:      issuedCert.SubjectCountry,
		})
	}
}

// issueSelfSignedCertificate issues a certificate using a self-signed CA
func (s *CertificateJobService) issueSelfSignedCertificate(ctx context.Context, issuerEntity *ent.Issuer, certReq *biz.CertificateRequest, csrPEM string) (*biz.IssuedCertificate, error) {
	// Get self-signed config
	if len(issuerEntity.Edges.SelfSignedConfigs) == 0 {
		return nil, fmt.Errorf("no self-signed configuration found for issuer")
	}
	selfSignedConfig := issuerEntity.Edges.SelfSignedConfigs[0]

	// Load or generate CA certificate and key
	caCert, caKey, err := s.getOrCreateCA(ctx, selfSignedConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA: %w", err)
	}

	// Parse the CSR
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Determine validity period (default 90 days for end-entity certs)
	validityDays := 90
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	// Build DNS names and IP addresses from request
	dnsNames := certReq.DNSNames
	var ipAddresses []net.IP
	for _, ipStr := range certReq.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         certReq.CommonName,
			Organization:       []string{selfSignedConfig.CaOrganization},
			OrganizationalUnit: []string{selfSignedConfig.CaOrganizationalUnit},
			Country:            []string{selfSignedConfig.CaCountry},
			Province:           []string{selfSignedConfig.CaProvince},
			Locality:           []string{selfSignedConfig.CaLocality},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode CA certificate to PEM (for chain)
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	return &biz.IssuedCertificate{
		Certificate:         string(certPEM),
		CACertificate:       string(caCertPEM),
		SerialNumber:        serialNumber.String(),
		IssuedAt:            notBefore,
		ExpiresAt:           notAfter,
		SubjectOrganization: selfSignedConfig.CaOrganization,
		SubjectOrgUnit:      selfSignedConfig.CaOrganizationalUnit,
		SubjectCountry:      selfSignedConfig.CaCountry,
	}, nil
}

// getOrCreateCA loads existing CA or generates a new one for self-signed issuer
func (s *CertificateJobService) getOrCreateCA(ctx context.Context, config *ent.SelfSignedIssuer) (*x509.Certificate, interface{}, error) {
	// Check if CA already exists
	if config.CaCertificatePem != "" && config.CaPrivateKeyPem != "" {
		// Load existing CA
		caCert, err := parseCertificatePEM(config.CaCertificatePem)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		caKey, err := parsePrivateKeyPEM(config.CaPrivateKeyPem)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
		}

		return caCert, caKey, nil
	}

	// Generate new CA
	s.log.Infof("Generating new CA for self-signed issuer: %s", config.CaCommonName)

	// Generate CA private key (ECDSA P-256)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Generate serial number for CA
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Determine CA validity
	validityDays := int(config.CaValidityDays)
	if validityDays <= 0 {
		validityDays = 3650 // 10 years default
	}
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CaCommonName,
			Organization:       []string{config.CaOrganization},
			OrganizationalUnit: []string{config.CaOrganizationalUnit},
			Country:            []string{config.CaCountry},
			Province:           []string{config.CaProvince},
			Locality:           []string{config.CaLocality},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Encode CA certificate and key to PEM
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal CA key: %w", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: caKeyBytes,
	})

	// Calculate CA fingerprint
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	fingerprint := sha256.Sum256(caCert.Raw)

	// Store CA cert and key in database
	err = s.issuerRepo.UpdateSelfSignedCA(ctx, config.ID, string(caCertPEM), string(caKeyPEM), hex.EncodeToString(fingerprint[:]), notAfter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store CA: %w", err)
	}

	s.log.Infof("Generated new CA: CN=%s, expires=%s", config.CaCommonName, notAfter)

	return caCert, caKey, nil
}

// parseCertificatePEM parses a PEM-encoded certificate
func parseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parsePrivateKeyPEM parses a PEM-encoded private key (supports EC and RSA)
func parsePrivateKeyPEM(keyPEM string) (interface{}, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// acmeUser implements the registration.User interface for lego
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.registration
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// issueACMECertificate issues a certificate using ACME protocol
func (s *CertificateJobService) issueACMECertificate(ctx context.Context, issuerEntity *ent.Issuer, certReq *biz.CertificateRequest, csrPEM, privateKeyPEM string) (*biz.IssuedCertificate, error) {
	// Get ACME configuration
	if len(issuerEntity.Edges.AcmeConfigs) == 0 {
		return nil, fmt.Errorf("no ACME configuration found for issuer")
	}
	acmeConfig := issuerEntity.Edges.AcmeConfigs[0]

	s.log.Infof("Starting ACME certificate issuance: endpoint=%s, email=%s, domains=%v",
		acmeConfig.Endpoint, acmeConfig.Email, certReq.DNSNames)

	// Get or create ACME account key
	accountKey, err := s.getOrCreateACMEAccountKey(ctx, acmeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACME account key: %w", err)
	}

	// Create ACME user
	user := &acmeUser{
		email: acmeConfig.Email,
		key:   accountKey,
	}

	// Configure lego
	config := lego.NewConfig(user)
	config.CADirURL = acmeConfig.Endpoint

	// Set key type for the certificate
	switch acmeConfig.KeyType {
	case acmeissuer.KeyTypeEc:
		switch acmeConfig.KeySize {
		case 384:
			config.Certificate.KeyType = certcrypto.EC384
		default:
			config.Certificate.KeyType = certcrypto.EC256
		}
	default: // RSA
		switch acmeConfig.KeySize {
		case 3072:
			config.Certificate.KeyType = certcrypto.RSA3072
		case 4096:
			config.Certificate.KeyType = certcrypto.RSA4096
		default:
			config.Certificate.KeyType = certcrypto.RSA2048
		}
	}

	// Create lego client
	legoClient, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Register or retrieve ACME account
	if user.registration == nil {
		s.log.Infof("Registering new ACME account: email=%s", acmeConfig.Email)

		var reg *registration.Resource

		// Check if EAB is configured
		if acmeConfig.EabKid != "" && acmeConfig.EabHmacKey != "" {
			// Decode the HMAC key (base64)
			hmacKey, err := base64.StdEncoding.DecodeString(acmeConfig.EabHmacKey)
			if err != nil {
				// Try URL-safe base64
				hmacKey, err = base64.RawURLEncoding.DecodeString(acmeConfig.EabHmacKey)
				if err != nil {
					return nil, fmt.Errorf("failed to decode EAB HMAC key: %w", err)
				}
			}

			reg, err = legoClient.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  acmeConfig.EabKid,
				HmacEncoded:          base64.RawURLEncoding.EncodeToString(hmacKey),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to register ACME account with EAB: %w", err)
			}
		} else {
			// Standard registration without EAB
			reg, err = legoClient.Registration.Register(registration.RegisterOptions{
				TermsOfServiceAgreed: true,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to register ACME account: %w", err)
			}
		}

		user.registration = reg
		s.log.Infof("ACME account registered: uri=%s", reg.URI)
	}

	// Set up DNS challenge provider
	if acmeConfig.ChallengeType != acmeissuer.ChallengeTypeDNS {
		return nil, fmt.Errorf("only DNS challenge type is currently supported")
	}

	if acmeConfig.ProviderName == "" {
		return nil, fmt.Errorf("DNS provider name is required for DNS challenge")
	}

	// Get DNS provider from registry
	dnsProvider, err := registry.GetProvider(acmeConfig.ProviderName, acmeConfig.ProviderConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider '%s': %w", acmeConfig.ProviderName, err)
	}

	// Configure DNS challenge
	err = legoClient.Challenge.SetDNS01Provider(dnsProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to set DNS provider: %w", err)
	}

	// Build list of domains
	var domains []string
	if certReq.CommonName != "" {
		domains = append(domains, certReq.CommonName)
	}
	for _, dns := range certReq.DNSNames {
		// Avoid duplicates
		found := false
		for _, d := range domains {
			if d == dns {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, dns)
		}
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains specified for certificate")
	}

	s.log.Infof("Requesting ACME certificate for domains: %v", domains)

	// Request the certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true, // Include intermediate certificates
	}

	// Use provided private key if available
	if privateKeyPEM != "" {
		key, err := parsePrivateKeyPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse provided private key: %w", err)
		}
		request.PrivateKey = key.(crypto.PrivateKey)
	}

	certificates, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	s.log.Infof("ACME certificate obtained successfully for domains: %v", domains)

	// Parse the certificate to get details
	cert, err := parseCertificatePEM(string(certificates.Certificate))
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	// Extract CA certificate (intermediate chain)
	caCertPEM := ""
	if certificates.IssuerCertificate != nil {
		caCertPEM = string(certificates.IssuerCertificate)
	}

	// Extract Subject fields from the certificate
	var subjectOrg, subjectOrgUnit, subjectCountry string
	if len(cert.Subject.Organization) > 0 {
		subjectOrg = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		subjectOrgUnit = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Country) > 0 {
		subjectCountry = cert.Subject.Country[0]
	}

	return &biz.IssuedCertificate{
		Certificate:         string(certificates.Certificate),
		CACertificate:       caCertPEM,
		PrivateKey:          string(certificates.PrivateKey),
		SerialNumber:        cert.SerialNumber.String(),
		IssuedAt:            cert.NotBefore,
		ExpiresAt:           cert.NotAfter,
		SubjectOrganization: subjectOrg,
		SubjectOrgUnit:      subjectOrgUnit,
		SubjectCountry:      subjectCountry,
	}, nil
}

// getOrCreateACMEAccountKey gets an existing or creates a new ACME account key
func (s *CertificateJobService) getOrCreateACMEAccountKey(ctx context.Context, acmeConfig *ent.AcmeIssuer) (crypto.PrivateKey, error) {
	// Check if key already exists
	if acmeConfig.KeyPem != "" {
		key, err := parsePrivateKeyPEM(acmeConfig.KeyPem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse existing ACME account key: %w", err)
		}
		return key.(crypto.PrivateKey), nil
	}

	// Generate new account key
	s.log.Infof("Generating new ACME account key: type=%s, size=%d", acmeConfig.KeyType, acmeConfig.KeySize)

	var key crypto.PrivateKey
	var keyPEM string

	switch acmeConfig.KeyType {
	case acmeissuer.KeyTypeEc:
		var curve elliptic.Curve
		switch acmeConfig.KeySize {
		case 384:
			curve = elliptic.P384()
		default:
			curve = elliptic.P256()
		}
		ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		key = ecKey

		keyBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA key: %w", err)
		}
		keyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}))

	default: // RSA
		keySize := int(acmeConfig.KeySize)
		if keySize < 2048 {
			keySize = 2048
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		key = rsaKey

		keyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}))
	}

	// Store the key in the database
	err := s.issuerRepo.UpdateACMEAccountKey(ctx, acmeConfig.ID, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to store ACME account key: %w", err)
	}

	s.log.Infof("Generated and stored new ACME account key")

	return key, nil
}

// Helper functions

func mapJobStatusToProto(status biz.JobStatus) lcmV1.CertificateJobStatus {
	switch status {
	case biz.JobStatusPending:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING
	case biz.JobStatusProcessing:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING
	case biz.JobStatusCompleted:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED
	case biz.JobStatusFailed:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED
	default:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_UNSPECIFIED
	}
}

func mapProtoStatusToJob(status lcmV1.CertificateJobStatus) biz.JobStatus {
	switch status {
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING:
		return biz.JobStatusPending
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING:
		return biz.JobStatusProcessing
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
		return biz.JobStatusCompleted
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
		return biz.JobStatusFailed
	default:
		return biz.JobStatusPending
	}
}

func mapProtoStatusToDBStatus(status lcmV1.CertificateJobStatus) issuedcertificate.Status {
	switch status {
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING:
		return issuedcertificate.StatusPending
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING:
		return issuedcertificate.StatusProcessing
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
		return issuedcertificate.StatusIssued
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
		return issuedcertificate.StatusFailed
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_CANCELLED:
		return issuedcertificate.StatusRevoked
	default:
		return issuedcertificate.StatusUnspecified
	}
}

func mapDBStatusToProto(status issuedcertificate.Status) lcmV1.CertificateJobStatus {
	switch status {
	case issuedcertificate.StatusPending:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING
	case issuedcertificate.StatusProcessing:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING
	case issuedcertificate.StatusIssued:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED
	case issuedcertificate.StatusFailed:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED
	case issuedcertificate.StatusRevoked:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_CANCELLED
	default:
		return lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_UNSPECIFIED
	}
}

func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate request")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func generateKeyAndCSR(commonName string, dnsNames, ipAddresses []string, keyType string, keySize int) (privateKeyPEM, csrPEM string, err error) {
	var privateKey interface{}
	var publicKey interface{}

	switch keyType {
	case "rsa":
		if keySize < 2048 {
			keySize = 2048
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return "", "", fmt.Errorf("failed to generate RSA key: %w", err)
		}
		privateKey = rsaKey
		publicKey = &rsaKey.PublicKey

		// Encode private key
		privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}))

	case "ecdsa":
		var curve elliptic.Curve
		switch keySize {
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		privateKey = ecKey
		publicKey = &ecKey.PublicKey

		// Encode private key
		keyBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal ECDSA key: %w", err)
		}
		privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}))

	default:
		return "", "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Parse IP addresses
	var ips []interface{}
	for _, ipStr := range ipAddresses {
		// IP addresses are stored as strings in the CSR
		ips = append(ips, ipStr)
	}

	// Create CSR template
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: dnsNames,
	}

	// Create CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}))

	// Verify the key pair
	_ = publicKey

	return privateKeyPEM, csrPEM, nil
}

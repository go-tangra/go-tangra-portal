package service

import (
	"context"
	"fmt"
	"net"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/cert"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/crypto"
)

// MtlsCertificateRequestService implements the LcmMtlsCertificateRequestService gRPC service
type MtlsCertificateRequestService struct {
	lcmV1.UnimplementedLcmMtlsCertificateRequestServiceServer

	log         *log.Helper
	requestRepo *data.MtlsCertificateRequestRepo
	certRepo    *data.MtlsCertificateRepo
	clientRepo  *data.LcmClientRepo
	config      *conf.LCM
	issuer      *crypto.MtlsIssuer
}

// NewMtlsCertificateRequestService creates a new MtlsCertificateRequestService
func NewMtlsCertificateRequestService(
	ctx *bootstrap.Context,
	requestRepo *data.MtlsCertificateRequestRepo,
	certRepo *data.MtlsCertificateRepo,
	clientRepo *data.LcmClientRepo,
) (*MtlsCertificateRequestService, error) {
	logger := ctx.NewLoggerHelper("lcm/service/mtls_certificate_request")

	// Get LCM config
	customConfig, ok := ctx.GetCustomConfig("lcm")
	if !ok {
		return nil, fmt.Errorf("lcm config not found")
	}
	lcmConfig, ok := customConfig.(*conf.LCM)
	if !ok {
		return nil, fmt.Errorf("invalid lcm config type")
	}

	// Use CertManager to ensure CA is loaded/generated (handles auto_generate_ca)
	certManager, err := cert.NewCertManager(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert manager: %w", err)
	}

	// GetServerTLSConfig will trigger CA generation if needed via loadCA()
	_, err = certManager.GetServerTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CA certificates: %w", err)
	}

	// Now the CA should exist, create the mTLS issuer
	issuer, err := crypto.NewMtlsIssuer(lcmConfig.GetCaCertPath(), lcmConfig.GetCaKeyPath())
	if err != nil {
		return nil, fmt.Errorf("failed to create mTLS issuer: %w", err)
	}

	logger.Info("MtlsCertificateRequestService initialized")

	return &MtlsCertificateRequestService{
		log:         logger,
		requestRepo: requestRepo,
		certRepo:    certRepo,
		clientRepo:  clientRepo,
		config:      lcmConfig,
		issuer:      issuer,
	}, nil
}

// ListMtlsCertificateRequests lists mTLS certificate requests with optional filters
func (s *MtlsCertificateRequestService) ListMtlsCertificateRequests(ctx context.Context, req *lcmV1.ListMtlsCertificateRequestsRequest) (*lcmV1.ListMtlsCertificateRequestsResponse, error) {
	s.log.Infof("Listing mTLS certificate requests with filters: status=%v, clientId=%v", req.GetStatus(), req.GetClientId())
	return s.requestRepo.ListWithFilters(ctx, req)
}

// GetMtlsCertificateRequest gets a single mTLS certificate request by query
func (s *MtlsCertificateRequestService) GetMtlsCertificateRequest(ctx context.Context, req *lcmV1.GetMtlsCertificateRequestRequest) (*lcmV1.GetMtlsCertificateRequestResponse, error) {
	request, err := s.requestRepo.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	return &lcmV1.GetMtlsCertificateRequestResponse{MtlsCertificateRequest: request}, nil
}

// CreateMtlsCertificateRequest creates a new mTLS certificate request
func (s *MtlsCertificateRequestService) CreateMtlsCertificateRequest(ctx context.Context, req *lcmV1.CreateMtlsCertificateRequestRequest) (*lcmV1.CreateMtlsCertificateRequestResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("request is required")
	}

	s.log.Infof("Creating mTLS certificate request for client: %s, CN: %s", req.GetClientId(), req.GetCommonName())

	// Validate CSR if provided
	if req.CsrPem != nil && req.GetCsrPem() != "" {
		_, err := crypto.ParseCSR(req.GetCsrPem())
		if err != nil {
			return nil, lcmV1.ErrorBadRequest("invalid CSR: " + err.Error())
		}
	}

	// Validate public key if provided
	if req.PublicKey != nil && req.GetPublicKey() != "" {
		_, err := crypto.ParsePublicKey(req.GetPublicKey())
		if err != nil {
			return nil, lcmV1.ErrorBadRequest("invalid public key: " + err.Error())
		}
	}

	// Create the request
	request, err := s.requestRepo.Create(ctx, req)
	if err != nil {
		s.log.Errorf("Failed to create certificate request: %v", err)
		return nil, err
	}

	s.log.Infof("Created mTLS certificate request with ID: %d, request_id: %s", request.GetId(), request.GetRequestId())

	return &lcmV1.CreateMtlsCertificateRequestResponse{MtlsCertificateRequest: request}, nil
}

// UpdateMtlsCertificateRequest updates an mTLS certificate request
func (s *MtlsCertificateRequestService) UpdateMtlsCertificateRequest(ctx context.Context, req *lcmV1.UpdateMtlsCertificateRequestRequest) (*lcmV1.UpdateMtlsCertificateRequestResponse, error) {
	if req == nil || req.Data == nil {
		return nil, lcmV1.ErrorBadRequest("request data is required")
	}

	s.log.Infof("Updating mTLS certificate request ID: %d", req.Data.GetId())

	request, err := s.requestRepo.Update(ctx, req)
	if err != nil {
		return nil, err
	}

	return &lcmV1.UpdateMtlsCertificateRequestResponse{MtlsCertificateRequest: request}, nil
}

// DeleteMtlsCertificateRequest soft-deletes an mTLS certificate request
func (s *MtlsCertificateRequestService) DeleteMtlsCertificateRequest(ctx context.Context, req *lcmV1.DeleteMtlsCertificateRequestRequest) (*lcmV1.DeleteMtlsCertificateRequestResponse, error) {
	s.log.Infof("Deleting mTLS certificate request ID: %d", req.GetId())

	request, err := s.requestRepo.Delete(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	return &lcmV1.DeleteMtlsCertificateRequestResponse{MtlsCertificateRequest: request}, nil
}

// ApproveMtlsCertificateRequest approves a certificate request and issues the certificate
func (s *MtlsCertificateRequestService) ApproveMtlsCertificateRequest(ctx context.Context, req *lcmV1.ApproveMtlsCertificateRequestRequest) (*lcmV1.ApproveMtlsCertificateRequestResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("request is required")
	}

	s.log.Infof("Approving mTLS certificate request ID: %d", req.GetId())

	// Get the existing request
	existingReq, err := s.requestRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	// Validate status - can only approve pending requests
	if existingReq.Status != nil && existingReq.GetStatus() != lcmV1.MtlsCertificateRequestStatus_MTLS_CERTIFICATE_REQUEST_STATUS_PENDING {
		return nil, lcmV1.ErrorBadRequest("can only approve pending requests")
	}

	// Approve the request in the database first
	// TODO: Get approvedBy from context/auth
	approvedReq, err := s.requestRepo.Approve(ctx, req, 0)
	if err != nil {
		return nil, err
	}

	// Now issue the certificate
	serialNumber, err := s.generateUniqueSerialNumber(ctx)
	if err != nil {
		s.log.Errorf("Failed to generate serial number: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to generate certificate serial number")
	}

	// Build certificate request from the approved request
	certReq := &crypto.CertificateRequest{
		ClientID:     existingReq.GetClientId(),
		CommonName:   existingReq.GetCommonName(),
		Organization: []string{"LCM"},
		Country:      []string{"US"},
		DNSNames:     existingReq.DnsNames,
		IsCA:         false,
		KeyAlgorithm: crypto.KeyAlgorithmRSA2048,
	}

	// Parse IP addresses
	if len(existingReq.IpAddresses) > 0 {
		ipAddresses := make([]net.IP, 0, len(existingReq.IpAddresses))
		for _, ipStr := range existingReq.IpAddresses {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				ipAddresses = append(ipAddresses, ip)
			}
		}
		certReq.IPAddresses = ipAddresses
	}

	// Set validity days
	validityDays := int(s.config.GetDefaultValidityDays())
	if req.ValidityDays != nil && req.GetValidityDays() > 0 {
		validityDays = int(req.GetValidityDays())
	} else if existingReq.ValidityDays != nil && existingReq.GetValidityDays() > 0 {
		validityDays = int(existingReq.GetValidityDays())
	}
	if validityDays <= 0 {
		validityDays = 365
	}
	certReq.ValidityDays = validityDays

	// Handle public key from request
	if existingReq.PublicKey != nil && existingReq.GetPublicKey() != "" {
		pubKey, err := crypto.ParsePublicKey(existingReq.GetPublicKey())
		if err != nil {
			s.log.Errorf("Failed to parse public key from request: %v", err)
			// Continue without public key - will generate new key pair
		} else {
			certReq.PublicKey = pubKey
		}
	}

	// Handle CSR from request
	if existingReq.CsrPem != nil && existingReq.GetCsrPem() != "" {
		csr, err := crypto.ParseCSR(existingReq.GetCsrPem())
		if err != nil {
			s.log.Errorf("Failed to parse CSR from request: %v", err)
		} else {
			certReq.CSR = csr
		}
	}

	// Issue the certificate
	issuedCert, err := s.issuer.IssueCertificate(certReq, serialNumber)
	if err != nil {
		s.log.Errorf("Failed to issue certificate: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to issue certificate: " + err.Error())
	}

	// Determine certificate type
	certType := lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT
	if existingReq.CertType != nil {
		certType = existingReq.GetCertType()
	}

	// Convert IP addresses to strings for storage
	ipStrings := make([]string, 0, len(certReq.IPAddresses))
	for _, ip := range certReq.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}

	// Build mTLS certificate data for database
	mtlsCertData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr(existingReq.GetClientId()),
		CommonName:         ptr(issuedCert.Certificate.Subject.CommonName),
		SubjectDn:          ptr(issuedCert.SubjectDN),
		IssuerDn:           ptr(issuedCert.IssuerDN),
		IssuerName:         ptr("lcm-root-ca"),
		FingerprintSha256:  ptr(issuedCert.FingerprintSHA256),
		FingerprintSha1:    ptr(issuedCert.FingerprintSHA1),
		PublicKeyAlgorithm: ptr(issuedCert.PublicKeyAlgorithm),
		PublicKeySize:      ptr(int32(issuedCert.PublicKeySize)),
		SignatureAlgorithm: ptr(issuedCert.SignatureAlgorithm),
		CertificatePem:     ptr(issuedCert.CertificatePEM),
		PublicKeyPem:       ptr(issuedCert.PublicKeyPEM),
		DnsNames:           certReq.DNSNames,
		IpAddresses:        ipStrings,
		CertType:           ptr(certType),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(false),
		KeyUsage:           issuedCert.KeyUsage,
		ExtKeyUsage:        issuedCert.ExtKeyUsage,
		Metadata:           existingReq.Metadata,
		RequestId:          ptr(req.GetId()),
	}

	// Save certificate to database
	savedCert, err := s.certRepo.Create(ctx, mtlsCertData)
	if err != nil {
		s.log.Errorf("Failed to save certificate to database: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to save certificate")
	}

	// Update the request with the certificate serial
	err = s.requestRepo.UpdateCertificateSerial(ctx, req.GetId(), serialNumber)
	if err != nil {
		s.log.Warnf("Failed to update request with certificate serial: %v", err)
		// Don't fail - certificate was issued successfully
	}

	// Include private key if one was generated
	if issuedCert.PrivateKeyPEM != "" {
		savedCert.CertificatePem = ptr(issuedCert.CertificatePEM + "\n" + issuedCert.PrivateKeyPEM)
	}

	s.log.Infof("Approved request ID: %d, issued certificate with serial: %d", req.GetId(), serialNumber)

	// Build ClientCertificate response for compatibility
	clientCert := &lcmV1.ClientCertificate{
		SerialNumber:   ptr(fmt.Sprintf("%d", serialNumber)),
		CommonName:     ptr(issuedCert.Certificate.Subject.CommonName),
		CertificatePem: savedCert.CertificatePem,
		Fingerprint:    ptr(issuedCert.FingerprintSHA256),
		Subject:        ptr(issuedCert.SubjectDN),
		IssuerDn:       ptr(issuedCert.IssuerDN),
		NotBefore:      ptr(issuedCert.NotBefore.Format("2006-01-02T15:04:05Z")),
		NotAfter:       ptr(issuedCert.NotAfter.Format("2006-01-02T15:04:05Z")),
		Status:         ptr(lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED),
	}

	return &lcmV1.ApproveMtlsCertificateRequestResponse{
		Request:     approvedReq,
		Certificate: clientCert,
	}, nil
}

// RejectMtlsCertificateRequest rejects a certificate request
func (s *MtlsCertificateRequestService) RejectMtlsCertificateRequest(ctx context.Context, req *lcmV1.RejectMtlsCertificateRequestRequest) (*lcmV1.RejectMtlsCertificateRequestResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("request is required")
	}

	s.log.Infof("Rejecting mTLS certificate request ID: %d, reason: %s", req.GetId(), req.GetReason())

	// Get the existing request to validate status
	existingReq, err := s.requestRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	// Validate status - can only reject pending requests
	if existingReq.Status != nil && existingReq.GetStatus() != lcmV1.MtlsCertificateRequestStatus_MTLS_CERTIFICATE_REQUEST_STATUS_PENDING {
		return nil, lcmV1.ErrorBadRequest("can only reject pending requests")
	}

	// TODO: Get rejectedBy from context/auth
	request, err := s.requestRepo.Reject(ctx, req, 0)
	if err != nil {
		return nil, err
	}

	return &lcmV1.RejectMtlsCertificateRequestResponse{MtlsCertificateRequest: request}, nil
}

// generateUniqueSerialNumber generates a unique serial number for certificates
func (s *MtlsCertificateRequestService) generateUniqueSerialNumber(ctx context.Context) (int64, error) {
	timestamp := crypto.GenerateSerialNumber()

	// Try to find a unique serial number
	for i := 0; i < 100; i++ {
		serialNumber := timestamp + int64(i)
		exists, err := s.certRepo.IsExistBySerialNumber(ctx, serialNumber)
		if err != nil {
			s.log.Warnf("Error checking serial number existence: %v", err)
			return timestamp, nil
		}
		if !exists {
			return serialNumber, nil
		}
	}

	return 0, fmt.Errorf("failed to generate unique serial number after 100 attempts")
}

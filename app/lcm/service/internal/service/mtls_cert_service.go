package service

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/cert"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/crypto"
)

// MtlsCertService implements the LcmMtlsCertService gRPC service
type MtlsCertService struct {
	lcmV1.UnimplementedLcmMtlsCertificateServiceServer

	log        *log.Helper
	certRepo   *data.MtlsCertificateRepo
	clientRepo *data.LcmClientRepo
	config     *conf.LCM
	issuer     *crypto.MtlsIssuer
}

// NewMtlsCertService creates a new MtlsCertService
func NewMtlsCertService(
	ctx *bootstrap.Context,
	certRepo *data.MtlsCertificateRepo,
	clientRepo *data.LcmClientRepo,
) (*MtlsCertService, error) {
	logger := ctx.NewLoggerHelper("lcm/service/mtls_cert")

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

	logger.Info("MtlsCertService initialized with CA certificate")

	return &MtlsCertService{
		log:        logger,
		certRepo:   certRepo,
		clientRepo: clientRepo,
		config:     lcmConfig,
		issuer:     issuer,
	}, nil
}

// ListMtlsCertificates lists mTLS certificates with optional filters
func (s *MtlsCertService) ListMtlsCertificates(ctx context.Context, req *lcmV1.ListMtlsCertificatesRequest) (*lcmV1.ListMtlsCertificatesResponse, error) {
	return s.certRepo.ListWithFilters(ctx, req)
}

// GetMtlsCertificate gets a single mTLS certificate by query
func (s *MtlsCertService) GetMtlsCertificate(ctx context.Context, req *lcmV1.GetMtlsCertificateRequest) (*lcmV1.GetMtlsCertificateResponse, error) {
	cert, err := s.certRepo.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	return &lcmV1.GetMtlsCertificateResponse{MtlsCertificate: cert}, nil
}

// IssueMtlsCertificate issues a new mTLS certificate
func (s *MtlsCertService) IssueMtlsCertificate(ctx context.Context, req *lcmV1.IssueMtlsCertificateRequest) (*lcmV1.IssueMtlsCertificateResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("request is required")
	}

	s.log.Infof("Issuing mTLS certificate for client: %s, CN: %s", req.GetClientId(), req.GetCommonName())

	// Validate client exists (optional - depends on business rules)
	// For now, we allow issuing certificates without client validation
	// as the certificate can be issued before client registration

	// Generate unique serial number
	serialNumber, err := s.generateUniqueSerialNumber(ctx)
	if err != nil {
		s.log.Errorf("Failed to generate serial number: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to generate certificate serial number")
	}

	// Build certificate request
	certReq := &crypto.CertificateRequest{
		ClientID:     req.GetClientId(),
		CommonName:   req.GetCommonName(),
		Organization: []string{"LCM"},
		Country:      []string{"US"},
		IsCA:         false,
		KeyAlgorithm: crypto.KeyAlgorithmRSA2048,
	}

	// Set validity days
	if req.ValidityDays != nil && req.GetValidityDays() > 0 {
		certReq.ValidityDays = int(req.GetValidityDays())
	} else if s.config.GetDefaultValidityDays() > 0 {
		certReq.ValidityDays = int(s.config.GetDefaultValidityDays())
	} else {
		certReq.ValidityDays = 365 // Default to 1 year
	}

	// Add DNS names
	if len(req.DnsNames) > 0 {
		certReq.DNSNames = req.DnsNames
	}

	// Add IP addresses
	if len(req.IpAddresses) > 0 {
		ipAddresses := make([]net.IP, 0, len(req.IpAddresses))
		for _, ipStr := range req.IpAddresses {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				ipAddresses = append(ipAddresses, ip)
			}
		}
		certReq.IPAddresses = ipAddresses
	}

	// Handle CSR if provided
	if req.CsrPem != nil && req.GetCsrPem() != "" {
		csr, err := crypto.ParseCSR(req.GetCsrPem())
		if err != nil {
			s.log.Errorf("Failed to parse CSR: %v", err)
			return nil, lcmV1.ErrorBadRequest("invalid CSR: " + err.Error())
		}
		certReq.CSR = csr
		// Use CSR's subject CN if not provided in request
		if req.CommonName == "" && csr.Subject.CommonName != "" {
			certReq.CommonName = csr.Subject.CommonName
		}
	} else if req.PublicKeyPem != nil && req.GetPublicKeyPem() != "" {
		// Handle public key if provided
		pubKey, err := crypto.ParsePublicKey(req.GetPublicKeyPem())
		if err != nil {
			s.log.Errorf("Failed to parse public key: %v", err)
			return nil, lcmV1.ErrorBadRequest("invalid public key: " + err.Error())
		}
		certReq.PublicKey = pubKey
	}
	// If neither CSR nor public key provided, a new key pair will be generated

	// Issue the certificate
	issuedCert, err := s.issuer.IssueCertificate(certReq, serialNumber)
	if err != nil {
		s.log.Errorf("Failed to issue certificate: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to issue certificate: " + err.Error())
	}

	// Determine certificate type
	certType := lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT
	if req.CertType != nil {
		certType = req.GetCertType()
	}

	// Convert IP addresses to strings for storage
	ipStrings := make([]string, 0, len(certReq.IPAddresses))
	for _, ip := range certReq.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}

	// Build mTLS certificate data for database
	mtlsCertData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr(req.GetClientId()),
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
		NotBefore:          timestamppb.New(issuedCert.NotBefore),
		NotAfter:           timestamppb.New(issuedCert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	// Add metadata if provided
	if len(req.Metadata) > 0 {
		mtlsCertData.Metadata = req.Metadata
	}

	// Add notes if provided
	if req.Notes != nil {
		mtlsCertData.Notes = req.Notes
	}

	// Save to database
	savedCert, err := s.certRepo.Create(ctx, mtlsCertData)
	if err != nil {
		s.log.Errorf("Failed to save certificate to database: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to save certificate")
	}

	s.log.Infof("Successfully issued mTLS certificate with serial: %d for client: %s", serialNumber, req.GetClientId())

	response := &lcmV1.IssueMtlsCertificateResponse{
		MtlsCertificate:  savedCert,
		CaCertificatePem: ptr(s.issuer.GetCACertificatePEM()),
	}

	// Include private key in response if one was generated (no CSR/public key provided)
	// Note: The private key should be handled securely by the caller
	// We don't store private keys in the database for security reasons
	if issuedCert.PrivateKeyPEM != "" {
		// For now, we return the private key in the certificate PEM field concatenated
		// In a production system, you might want a separate secure channel for this
		savedCert.CertificatePem = ptr(issuedCert.CertificatePEM + "\n" + issuedCert.PrivateKeyPEM)
	}

	return response, nil
}

// UpdateMtlsCertificate updates certificate metadata
func (s *MtlsCertService) UpdateMtlsCertificate(ctx context.Context, req *lcmV1.UpdateMtlsCertificateRequest) (*lcmV1.UpdateMtlsCertificateResponse, error) {
	cert, err := s.certRepo.Update(ctx, req)
	if err != nil {
		return nil, err
	}
	return &lcmV1.UpdateMtlsCertificateResponse{MtlsCertificate: cert}, nil
}

// RevokeMtlsCertificate revokes a certificate
func (s *MtlsCertService) RevokeMtlsCertificate(ctx context.Context, req *lcmV1.RevokeMtlsCertificateRequest) (*lcmV1.RevokeMtlsCertificateResponse, error) {
	// TODO: Get revokedBy from context/auth
	cert, err := s.certRepo.Revoke(ctx, req, 0)
	if err != nil {
		return nil, err
	}
	return &lcmV1.RevokeMtlsCertificateResponse{MtlsCertificate: cert}, nil
}

// RenewMtlsCertificate renews a certificate
func (s *MtlsCertService) RenewMtlsCertificate(ctx context.Context, req *lcmV1.RenewMtlsCertificateRequest) (*lcmV1.RenewMtlsCertificateResponse, error) {
	if req == nil {
		return nil, lcmV1.ErrorBadRequest("request is required")
	}

	s.log.Infof("Renewing mTLS certificate with serial: %d", req.GetSerialNumber())

	// Get the existing certificate
	oldCert, err := s.certRepo.GetBySerialNumber(ctx, req.GetSerialNumber())
	if err != nil {
		s.log.Errorf("Failed to get certificate for renewal: %v", err)
		return nil, err
	}

	// Validate certificate status - can only renew active or expiring certificates
	if oldCert.Status != nil {
		status := oldCert.GetStatus()
		if status == lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_REVOKED {
			return nil, lcmV1.ErrorBadRequest("cannot renew a revoked certificate")
		}
	}

	// Generate unique serial number for the new certificate
	newSerialNumber, err := s.generateUniqueSerialNumber(ctx)
	if err != nil {
		s.log.Errorf("Failed to generate serial number for renewal: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to generate certificate serial number")
	}

	// Build certificate request from old certificate data
	certReq := &crypto.CertificateRequest{
		ClientID:     oldCert.GetClientId(),
		CommonName:   oldCert.GetCommonName(),
		Organization: []string{"LCM"},
		Country:      []string{"US"},
		DNSNames:     oldCert.DnsNames,
		IsCA:         oldCert.GetIsCa(),
		KeyAlgorithm: crypto.KeyAlgorithmRSA2048,
	}

	// Parse IP addresses from old certificate
	if len(oldCert.IpAddresses) > 0 {
		ipAddresses := make([]net.IP, 0, len(oldCert.IpAddresses))
		for _, ipStr := range oldCert.IpAddresses {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				ipAddresses = append(ipAddresses, ip)
			}
		}
		certReq.IPAddresses = ipAddresses
	}

	// Set validity days
	if req.ValidityDays != nil && req.GetValidityDays() > 0 {
		certReq.ValidityDays = int(req.GetValidityDays())
	} else if s.config.GetDefaultValidityDays() > 0 {
		certReq.ValidityDays = int(s.config.GetDefaultValidityDays())
	} else {
		certReq.ValidityDays = 365
	}

	// Handle public key for renewal
	if req.PublicKeyPem != nil && req.GetPublicKeyPem() != "" {
		// New public key provided - use it
		pubKey, err := crypto.ParsePublicKey(req.GetPublicKeyPem())
		if err != nil {
			s.log.Errorf("Failed to parse public key for renewal: %v", err)
			return nil, lcmV1.ErrorBadRequest("invalid public key: " + err.Error())
		}
		certReq.PublicKey = pubKey
	} else if oldCert.PublicKeyPem != nil && oldCert.GetPublicKeyPem() != "" {
		// Reuse old public key
		pubKey, err := crypto.ParsePublicKey(oldCert.GetPublicKeyPem())
		if err != nil {
			s.log.Errorf("Failed to parse old public key for renewal: %v", err)
			// If we can't parse the old key, generate a new one
			// A new key pair will be generated by the issuer
		} else {
			certReq.PublicKey = pubKey
		}
	}
	// If no public key available, a new key pair will be generated

	// Issue the new certificate
	issuedCert, err := s.issuer.IssueCertificate(certReq, newSerialNumber)
	if err != nil {
		s.log.Errorf("Failed to issue renewal certificate: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to issue renewal certificate: " + err.Error())
	}

	// Convert IP addresses to strings for storage
	ipStrings := make([]string, 0, len(certReq.IPAddresses))
	for _, ip := range certReq.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}

	// Build new mTLS certificate data
	newCertData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(newSerialNumber),
		ClientId:           oldCert.ClientId,
		CommonName:         ptr(issuedCert.Certificate.Subject.CommonName),
		SubjectDn:          ptr(issuedCert.SubjectDN),
		IssuerDn:           ptr(issuedCert.IssuerDN),
		IssuerName:         oldCert.IssuerName,
		FingerprintSha256:  ptr(issuedCert.FingerprintSHA256),
		FingerprintSha1:    ptr(issuedCert.FingerprintSHA1),
		PublicKeyAlgorithm: ptr(issuedCert.PublicKeyAlgorithm),
		PublicKeySize:      ptr(int32(issuedCert.PublicKeySize)),
		SignatureAlgorithm: ptr(issuedCert.SignatureAlgorithm),
		CertificatePem:     ptr(issuedCert.CertificatePEM),
		PublicKeyPem:       ptr(issuedCert.PublicKeyPEM),
		DnsNames:           certReq.DNSNames,
		IpAddresses:        ipStrings,
		CertType:           oldCert.CertType,
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               oldCert.IsCa,
		KeyUsage:           issuedCert.KeyUsage,
		ExtKeyUsage:        issuedCert.ExtKeyUsage,
		Metadata:           oldCert.Metadata,
		NotBefore:          timestamppb.New(issuedCert.NotBefore),
		NotAfter:           timestamppb.New(issuedCert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	// Save new certificate to database
	savedNewCert, err := s.certRepo.Create(ctx, newCertData)
	if err != nil {
		s.log.Errorf("Failed to save renewal certificate to database: %v", err)
		return nil, lcmV1.ErrorInternalServerError("failed to save renewal certificate")
	}

	// Optionally revoke the old certificate
	var updatedOldCert *lcmV1.MtlsCertificate
	if req.RevokeOld != nil && req.GetRevokeOld() {
		revokeReq := &lcmV1.RevokeMtlsCertificateRequest{
			SerialNumber: req.GetSerialNumber(),
			Reason:       lcmV1.MtlsCertificateRevocationReason_MTLS_CERT_REVOCATION_REASON_SUPERSEDED,
			Notes:        ptr(fmt.Sprintf("Superseded by certificate with serial: %d", newSerialNumber)),
		}
		updatedOldCert, err = s.certRepo.Revoke(ctx, revokeReq, 0)
		if err != nil {
			s.log.Warnf("Failed to revoke old certificate during renewal: %v", err)
			// Don't fail the renewal, just log the warning
			updatedOldCert = oldCert
		}
	} else {
		updatedOldCert = oldCert
	}

	// Include private key if one was generated
	if issuedCert.PrivateKeyPEM != "" {
		savedNewCert.CertificatePem = ptr(issuedCert.CertificatePEM + "\n" + issuedCert.PrivateKeyPEM)
	}

	s.log.Infof("Successfully renewed mTLS certificate. Old serial: %d, New serial: %d", req.GetSerialNumber(), newSerialNumber)

	return &lcmV1.RenewMtlsCertificateResponse{
		MtlsCertificate:    savedNewCert,
		OldMtlsCertificate: updatedOldCert,
	}, nil
}

// DeleteMtlsCertificate soft-deletes a certificate
func (s *MtlsCertService) DeleteMtlsCertificate(ctx context.Context, req *lcmV1.DeleteMtlsCertificateRequest) (*lcmV1.DeleteMtlsCertificateResponse, error) {
	cert, err := s.certRepo.Delete(ctx, req.GetSerialNumber())
	if err != nil {
		return nil, err
	}
	return &lcmV1.DeleteMtlsCertificateResponse{MtlsCertificate: cert}, nil
}

// DownloadMtlsCertificate downloads a certificate PEM
func (s *MtlsCertService) DownloadMtlsCertificate(ctx context.Context, req *lcmV1.DownloadMtlsCertificateRequest) (*lcmV1.DownloadMtlsCertificateResponse, error) {
	resp, err := s.certRepo.Download(ctx, req.GetSerialNumber(), req.GetIncludeChain())
	if err != nil {
		return nil, err
	}

	// Add CA certificate if chain is requested
	if req.GetIncludeChain() {
		caPEM := s.issuer.GetCACertificatePEM()
		resp.CaCertificatePem = &caPEM
		// Build full chain: certificate + CA
		chainPEM := resp.CertificatePem + "\n" + caPEM
		resp.ChainPem = &chainPEM
	}

	return resp, nil
}

// generateUniqueSerialNumber generates a unique serial number for certificates
func (s *MtlsCertService) generateUniqueSerialNumber(ctx context.Context) (int64, error) {
	// Use timestamp-based serial with collision checking
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Try to find a unique serial number
	for i := 0; i < 100; i++ {
		serialNumber := timestamp + int64(i)
		exists, err := s.certRepo.IsExistBySerialNumber(ctx, serialNumber)
		if err != nil {
			s.log.Warnf("Error checking serial number existence: %v", err)
			// If database check fails, use the timestamp directly
			return timestamp, nil
		}
		if !exists {
			return serialNumber, nil
		}
	}

	return 0, fmt.Errorf("failed to generate unique serial number after 100 attempts")
}

// ptr is a helper function to create a pointer to a value
func ptr[T any](v T) *T {
	return &v
}

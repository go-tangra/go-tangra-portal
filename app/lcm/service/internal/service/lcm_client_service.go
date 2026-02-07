package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/redis/go-redis/v9"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/cert"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/ent/mtlscertificaterequest"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/event"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

// LcmClientService implements the LcmClientService gRPC service
type LcmClientService struct {
	lcmV1.UnimplementedLcmClientServiceServer

	log              *log.Helper
	certManager      *cert.CertManager
	clientRepo       *data.LcmClientRepo
	requestRepo      *data.MtlsCertificateRequestRepo
	certRepo         *data.MtlsCertificateRepo
	tenantSecretRepo *data.TenantSecretRepo
	redisClient      *redis.Client
	topicPrefix      string
}

// NewLcmClientService creates a new LcmClientService
func NewLcmClientService(
	ctx *bootstrap.Context,
	certManager *cert.CertManager,
	clientRepo *data.LcmClientRepo,
	requestRepo *data.MtlsCertificateRequestRepo,
	certRepo *data.MtlsCertificateRepo,
	tenantSecretRepo *data.TenantSecretRepo,
	redisClient *redis.Client,
) *LcmClientService {
	topicPrefix := "lcm"
	customConfig, ok := ctx.GetCustomConfig("lcm")
	if ok {
		if lcmConfig, ok := customConfig.(interface{ GetEvents() interface{ GetTopicPrefix() string } }); ok {
			if events := lcmConfig.GetEvents(); events != nil && events.GetTopicPrefix() != "" {
				topicPrefix = events.GetTopicPrefix()
			}
		}
	}

	return &LcmClientService{
		log:              ctx.NewLoggerHelper("lcm/service/client"),
		certManager:      certManager,
		clientRepo:       clientRepo,
		requestRepo:      requestRepo,
		certRepo:         certRepo,
		tenantSecretRepo: tenantSecretRepo,
		redisClient:      redisClient,
		topicPrefix:      topicPrefix,
	}
}

// RegisterLcmClient handles client registration and certificate requests
func (s *LcmClientService) RegisterLcmClient(ctx context.Context, req *lcmV1.CreateLcmClientRequest) (*lcmV1.CreateLcmClientResponse, error) {
	s.log.Infof("RegisterLcmClient: client_id=%s, hostname=%s", req.GetClientId(), req.GetHostname())

	// Validate shared secret and get tenant ID
	var tenantID uint32
	config := s.certManager.GetConfig()

	if req.SharedSecret != nil && *req.SharedSecret != "" {
		// First try to look up tenant from the shared secret
		tid, err := s.tenantSecretRepo.GetTenantIDBySecret(ctx, *req.SharedSecret)
		if err != nil {
			s.log.Errorf("Failed to lookup tenant secret: %v", err)
			return nil, lcmV1.ErrorInternalServerError("failed to validate shared secret")
		}
		if tid > 0 {
			tenantID = tid
			s.log.Infof("Client %s authenticated with tenant-specific secret (tenant_id=%d)", req.GetClientId(), tenantID)
		} else if config.GetSharedSecret() != "" && *req.SharedSecret == config.GetSharedSecret() {
			// Fall back to global shared secret (platform-level operation, tenant_id = 0)
			tenantID = 0
			s.log.Infof("Client %s authenticated with global shared secret", req.GetClientId())
		} else {
			s.log.Warnf("Invalid shared secret for client %s", req.GetClientId())
			return nil, lcmV1.ErrorUnauthorized("invalid shared secret")
		}
	} else if config.GetSharedSecret() != "" {
		// Shared secret required but not provided
		s.log.Warnf("Missing shared secret for client %s", req.GetClientId())
		return nil, lcmV1.ErrorUnauthorized("shared secret required")
	}

	// Validate public key format
	block, _ := pem.Decode([]byte(req.GetPublicKey()))
	if block == nil {
		return nil, lcmV1.ErrorBadRequest("invalid public key format")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, lcmV1.ErrorBadRequest("invalid public key: %v", err)
	}

	// Get or create client record (scoped by tenant)
	client, err := s.clientRepo.GetByTenantAndClientID(ctx, tenantID, req.GetClientId())
	if err != nil {
		return nil, err
	}
	if client == nil {
		// Create new client
		client, err = s.clientRepo.Create(ctx, tenantID, req.GetClientId(), req.GetMetadata())
		if err != nil {
			return nil, err
		}
		s.log.Infof("Created new client: %s (tenant_id=%d)", req.GetClientId(), tenantID)
	} else {
		// Update existing client metadata
		client, err = s.clientRepo.Update(ctx, client.ID, req.GetMetadata())
		if err != nil {
			return nil, err
		}
		s.log.Infof("Updated existing client: %s (tenant_id=%d)", req.GetClientId(), tenantID)
	}

	// Create certificate request (with tenant)
	certRequest, err := s.requestRepo.CreateFromRegistration(
		ctx,
		tenantID,
		req.GetClientId(),
		req.GetHostname(),
		req.GetPublicKey(),
		req.GetDnsNames(),
		req.GetIpAddresses(),
		req.GetMetadata(),
	)
	if err != nil {
		return nil, err
	}

	response := &lcmV1.CreateLcmClientResponse{
		Client: s.clientRepo.ToProto(client),
	}

	// Check if auto-approve is enabled
	if config.GetAutoApproveCertificates() {
		s.log.Infof("Auto-approving certificate for client %s", req.GetClientId())

		// Sign the certificate
		certPEM, serialNumber, err := s.certManager.SignClientCertificate(
			req.GetPublicKey(),
			req.GetHostname(),
			req.GetDnsNames(),
			req.GetIpAddresses(),
			int(config.GetDefaultValidityDays()),
		)
		if err != nil {
			s.log.Errorf("Failed to sign certificate: %v", err)
			// Return pending status if signing fails
			response.Certificate = s.createPendingCertificateResponse(certRequest.RequestID)
			return response, nil
		}

		// Parse certificate to get details
		certBlock, _ := pem.Decode([]byte(certPEM))
		parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			s.log.Errorf("Failed to parse signed certificate: %v", err)
			response.Certificate = s.createPendingCertificateResponse(certRequest.RequestID)
			return response, nil
		}

		// Store certificate in database
		clientID := req.GetClientId()
		hostname := req.GetHostname()
		_, err = s.certRepo.Create(ctx, &lcmV1.MtlsCertificate{
			SerialNumber:      &serialNumber,
			ClientId:          &clientID,
			CommonName:        &hostname,
			SubjectDn:         strPtr(parsedCert.Subject.String()),
			IssuerDn:          strPtr(parsedCert.Issuer.String()),
			FingerprintSha256: strPtr(fingerprintSHA256(parsedCert)),
			CertificatePem:    &certPEM,
			NotBefore:         timestamppb.New(parsedCert.NotBefore),
			NotAfter:          timestamppb.New(parsedCert.NotAfter),
			Status:            lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE.Enum(),
			CertType:          lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT.Enum(),
			DnsNames:          req.GetDnsNames(),
			IpAddresses:       req.GetIpAddresses(),
		})
		if err != nil {
			s.log.Errorf("Failed to store certificate: %v", err)
			// Still return the certificate even if storage fails
		}

		// Mark request as issued
		if err := s.requestRepo.MarkAsIssued(ctx, certRequest.ID, serialNumber); err != nil {
			s.log.Errorf("Failed to mark request as issued: %v", err)
		}

		// Get CA certificate
		caCertPEM, err := s.certManager.GetCACertificatePEM()
		if err != nil {
			s.log.Errorf("Failed to get CA certificate: %v", err)
		}

		serialNumStr := formatSerialNumber(serialNumber)
		notBeforeStr := parsedCert.NotBefore.Format(time.RFC3339)
		notAfterStr := parsedCert.NotAfter.Format(time.RFC3339)
		response.Certificate = &lcmV1.ClientCertificate{
			RequestId:      &certRequest.RequestID,
			SerialNumber:   &serialNumStr,
			Status:         lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED.Enum(),
			CertificatePem: &certPEM,
			NotBefore:      &notBeforeStr,
			NotAfter:       &notAfterStr,
		}
		response.CaCertificate = &caCertPEM
	} else {
		// Certificate pending approval
		response.Certificate = s.createPendingCertificateResponse(certRequest.RequestID)
	}

	return response, nil
}

// GetRequestStatus checks the status of a certificate request
func (s *LcmClientService) GetRequestStatus(ctx context.Context, req *lcmV1.GetRequestStatusRequest) (*lcmV1.GetRequestStatusResponse, error) {
	s.log.Infof("GetRequestStatus: request_id=%s, client_id=%s", req.GetRequestId(), req.GetClientId())

	// Get the certificate request
	certRequest, err := s.requestRepo.GetByRequestIDAndClientID(ctx, req.GetRequestId(), req.GetClientId())
	if err != nil {
		return nil, err
	}

	response := &lcmV1.GetRequestStatusResponse{}
	if certRequest.CreateTime != nil {
		response.CreateTime = timestamppb.New(*certRequest.CreateTime)
	}

	// Map status
	if certRequest.Status != nil {
		switch *certRequest.Status {
		case mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_PENDING:
			response.Status = lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING
			msg := "Certificate request is pending approval"
			response.Message = &msg
		case mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_APPROVED:
			response.Status = lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED
			msg := "Certificate request approved, ready for download"
			response.Message = &msg
		case mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_ISSUED:
			response.Status = lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED
			msg := "Certificate has been issued"
			response.Message = &msg
		case mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_REJECTED:
			response.Status = lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED
			if certRequest.RejectReason != "" {
				response.Message = &certRequest.RejectReason
			}
		case mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_CANCELLED:
			response.Status = lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED
			msg := "Certificate request was cancelled"
			response.Message = &msg
		default:
			response.Status = lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_UNKNOWN
		}
	} else {
		response.Status = lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_UNKNOWN
	}

	if certRequest.UpdateTime != nil {
		response.UpdateTime = timestamppb.New(*certRequest.UpdateTime)
	}

	return response, nil
}

// DownloadClientCertificate downloads an issued certificate
func (s *LcmClientService) DownloadClientCertificate(ctx context.Context, req *lcmV1.DownloadClientCertificateRequest) (*lcmV1.DownloadClientCertificateResponse, error) {
	s.log.Infof("DownloadClientCertificate: request_id=%s, client_id=%s", req.GetRequestId(), req.GetClientId())

	// Get the certificate request
	certRequest, err := s.requestRepo.GetByRequestIDAndClientID(ctx, req.GetRequestId(), req.GetClientId())
	if err != nil {
		return nil, err
	}

	// Check if request is approved/issued
	if certRequest.Status != nil {
		switch *certRequest.Status {
		case mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_PENDING:
			return &lcmV1.DownloadClientCertificateResponse{
				Status: lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING,
			}, nil
		case mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_REJECTED,
			mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_CANCELLED:
			return &lcmV1.DownloadClientCertificateResponse{
				Status: lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED,
			}, nil
		}
	}

	// Verify public key matches
	if req.GetPublicKey() != certRequest.PublicKey {
		s.log.Warnf("Public key mismatch for request %s", req.GetRequestId())
		return nil, lcmV1.ErrorUnauthorized("public key does not match")
	}

	// If already issued, get the certificate from database
	if certRequest.CertificateSerial != nil {
		cert, err := s.certRepo.GetBySerialNumber(ctx, *certRequest.CertificateSerial)
		if err == nil && cert != nil {
			caCertPEM, _ := s.certManager.GetCACertificatePEM()
			return &lcmV1.DownloadClientCertificateResponse{
				CertificatePem:   cert.CertificatePem,
				CaCertificatePem: &caCertPEM,
				Status:           lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED,
			}, nil
		}
	}

	// If approved but not yet issued, sign the certificate now
	if certRequest.Status != nil && *certRequest.Status == mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_APPROVED {
		config := s.certManager.GetConfig()
		validityDays := int(config.GetDefaultValidityDays())
		if certRequest.ValidityDays != nil {
			validityDays = int(*certRequest.ValidityDays)
		}

		certPEM, serialNumber, err := s.certManager.SignClientCertificate(
			certRequest.PublicKey,
			certRequest.CommonName,
			certRequest.DNSNames,
			certRequest.IPAddresses,
			validityDays,
		)
		if err != nil {
			s.log.Errorf("Failed to sign certificate: %v", err)
			return nil, lcmV1.ErrorInternalServerError("failed to sign certificate")
		}

		// Parse certificate to get details
		certBlock, _ := pem.Decode([]byte(certPEM))
		parsedCert, _ := x509.ParseCertificate(certBlock.Bytes)

		// Store certificate
		clientID := certRequest.ClientID
		commonName := certRequest.CommonName
		_, err = s.certRepo.Create(ctx, &lcmV1.MtlsCertificate{
			SerialNumber:      &serialNumber,
			ClientId:          &clientID,
			CommonName:        &commonName,
			SubjectDn:         strPtr(parsedCert.Subject.String()),
			IssuerDn:          strPtr(parsedCert.Issuer.String()),
			FingerprintSha256: strPtr(fingerprintSHA256(parsedCert)),
			CertificatePem:    &certPEM,
			NotBefore:         timestamppb.New(parsedCert.NotBefore),
			NotAfter:          timestamppb.New(parsedCert.NotAfter),
			Status:            lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE.Enum(),
			CertType:          lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT.Enum(),
			DnsNames:          certRequest.DNSNames,
			IpAddresses:       certRequest.IPAddresses,
		})
		if err != nil {
			s.log.Errorf("Failed to store certificate: %v", err)
		}

		// Mark as issued
		if err := s.requestRepo.MarkAsIssued(ctx, certRequest.ID, serialNumber); err != nil {
			s.log.Errorf("Failed to mark request as issued: %v", err)
		}

		caCertPEM, _ := s.certManager.GetCACertificatePEM()
		return &lcmV1.DownloadClientCertificateResponse{
			CertificatePem:   &certPEM,
			CaCertificatePem: &caCertPEM,
			Status:           lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED,
		}, nil
	}

	// Already issued status but no certificate found
	if certRequest.Status != nil && *certRequest.Status == mtlscertificaterequest.StatusMTLS_CERTIFICATE_REQUEST_STATUS_ISSUED {
		return nil, lcmV1.ErrorInternalServerError("certificate was issued but not found in database")
	}

	return &lcmV1.DownloadClientCertificateResponse{
		Status: lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING,
	}, nil
}

// Helper functions

func (s *LcmClientService) createPendingCertificateResponse(requestID string) *lcmV1.ClientCertificate {
	return &lcmV1.ClientCertificate{
		RequestId: &requestID,
		Status:    lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING.Enum(),
	}
}

func strPtr(s string) *string {
	return &s
}

func formatSerialNumber(serial int64) string {
	return fmt.Sprintf("%d", serial)
}

func fingerprintSHA256(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// ListClientCertificates lists all certificates for the authenticated client
func (s *LcmClientService) ListClientCertificates(ctx context.Context, req *lcmV1.ListClientCertificatesRequest) (*lcmV1.ListClientCertificatesResponse, error) {
	// Get client ID from mTLS certificate or request
	clientID := client.GetClientID(ctx)
	if req.GetClientId() != "" {
		// Verify that the requested client_id matches the authenticated client
		if clientID != "" && clientID != req.GetClientId() {
			return nil, lcmV1.ErrorForbidden("client ID does not match authenticated certificate")
		}
		clientID = req.GetClientId()
	}

	if clientID == "" {
		return nil, lcmV1.ErrorUnauthorized("client authentication required")
	}

	s.log.Infof("ListClientCertificates: client_id=%s", clientID)

	// Get all mTLS certificates for this client
	certs, err := s.certRepo.GetCertificatesByClientID(ctx, clientID)
	if err != nil {
		s.log.Errorf("Failed to get certificates for client %s: %v", clientID, err)
		return nil, lcmV1.ErrorInternalServerError("failed to retrieve certificates")
	}

	// Convert to response format
	response := &lcmV1.ListClientCertificatesResponse{
		Certificates: make([]*lcmV1.CertificateInfo, 0, len(certs)),
	}

	for _, cert := range certs {
		certInfo := &lcmV1.CertificateInfo{
			Name:         cert.GetCommonName(),
			SerialNumber: formatSerialNumber(cert.GetSerialNumber()),
			CommonName:   cert.GetCommonName(),
			DnsNames:     cert.GetDnsNames(),
			IpAddresses:  cert.GetIpAddresses(),
			IssuerName:   cert.GetIssuerDn(),
			Status:       mapCertStatusToClientStatus(cert.GetStatus()),
		}

		// Set timestamps
		if cert.GetIssuedAt() != nil {
			certInfo.IssuedAt = cert.GetIssuedAt()
		} else if cert.GetNotBefore() != nil {
			certInfo.IssuedAt = cert.GetNotBefore()
		}
		if cert.GetNotAfter() != nil {
			certInfo.ExpiresAt = cert.GetNotAfter()
		}

		// Include fingerprint
		if cert.FingerprintSha256 != nil {
			certInfo.FingerprintSha256 = cert.FingerprintSha256
		}

		// Include certificate PEM if requested
		if req.GetIncludeCertificatePem() && cert.CertificatePem != nil {
			certInfo.CertificatePem = cert.CertificatePem
		}

		response.Certificates = append(response.Certificates, certInfo)
	}

	// Include CA certificate
	if len(response.Certificates) > 0 {
		caCertPEM, err := s.certManager.GetCACertificatePEM()
		if err == nil {
			response.CaCertificatePem = &caCertPEM
		}
	}

	return response, nil
}

// StreamCertificateUpdates streams certificate updates to the client
func (s *LcmClientService) StreamCertificateUpdates(req *lcmV1.StreamCertificateUpdatesRequest, stream grpc.ServerStreamingServer[lcmV1.CertificateUpdateEvent]) error {
	ctx := stream.Context()

	// Get client ID from mTLS certificate or request
	clientID := client.GetClientID(ctx)
	if req.GetClientId() != "" {
		if clientID != "" && clientID != req.GetClientId() {
			return lcmV1.ErrorForbidden("client ID does not match authenticated certificate")
		}
		clientID = req.GetClientId()
	}

	if clientID == "" {
		return lcmV1.ErrorUnauthorized("client authentication required")
	}

	s.log.Infof("StreamCertificateUpdates: client_id=%s connected", clientID)

	if s.redisClient == nil {
		return lcmV1.ErrorInternalServerError("event streaming not available")
	}

	// Subscribe to certificate events for this client
	patterns := []string{
		s.topicPrefix + ".certificate.*",
		s.topicPrefix + ".renewal.*",
	}
	pubsub := s.redisClient.PSubscribe(ctx, patterns...)
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			s.log.Infof("StreamCertificateUpdates: client_id=%s disconnected", clientID)
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return nil
			}

			// Parse the event
			updateEvent, err := s.parseEventForClient(msg, clientID)
			if err != nil {
				s.log.Debugf("Skipping event: %v", err)
				continue
			}
			if updateEvent == nil {
				continue // Event not for this client
			}

			// Send to client
			if err := stream.Send(updateEvent); err != nil {
				s.log.Errorf("Failed to send event to client %s: %v", clientID, err)
				return err
			}
			s.log.Debugf("Sent certificate update to client %s: %s", clientID, updateEvent.EventType)
		}
	}
}

// parseEventForClient parses a Redis message and returns a CertificateUpdateEvent if it's for the given client
func (s *LcmClientService) parseEventForClient(msg *redis.Message, clientID string) (*lcmV1.CertificateUpdateEvent, error) {
	// Parse the LCM event
	var lcmEvent event.LCMEvent
	if err := json.Unmarshal([]byte(msg.Payload), &lcmEvent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	// Extract client ID from the event data
	eventClientID := extractClientIDFromEvent(lcmEvent.Data)
	if eventClientID == "" || eventClientID != clientID {
		return nil, nil // Not for this client
	}

	// Determine event type
	eventType := mapTopicToUpdateType(msg.Channel)
	if eventType == lcmV1.CertificateUpdateType_CERTIFICATE_UPDATE_UNSPECIFIED {
		return nil, nil // Unknown event type
	}

	// Build certificate info from event data
	certInfo := buildCertInfoFromEvent(lcmEvent.Data)

	updateEvent := &lcmV1.CertificateUpdateEvent{
		EventType: eventType,
		EventTime: timestamppb.Now(),
	}

	if certInfo != nil {
		updateEvent.Certificate = certInfo
	}

	// Include CA certificate for issued/renewed events
	if eventType == lcmV1.CertificateUpdateType_CERTIFICATE_ISSUED || eventType == lcmV1.CertificateUpdateType_CERTIFICATE_RENEWED {
		caCertPEM, err := s.certManager.GetCACertificatePEM()
		if err == nil {
			updateEvent.CaCertificatePem = &caCertPEM
		}
	}

	return updateEvent, nil
}

// mapTopicToUpdateType maps Redis topic to CertificateUpdateType
func mapTopicToUpdateType(topic string) lcmV1.CertificateUpdateType {
	switch {
	case strings.HasSuffix(topic, ".certificate.issued"):
		return lcmV1.CertificateUpdateType_CERTIFICATE_ISSUED
	case strings.HasSuffix(topic, ".renewal.completed"):
		return lcmV1.CertificateUpdateType_CERTIFICATE_RENEWED
	case strings.HasSuffix(topic, ".certificate.revoked"):
		return lcmV1.CertificateUpdateType_CERTIFICATE_REVOKED
	default:
		return lcmV1.CertificateUpdateType_CERTIFICATE_UPDATE_UNSPECIFIED
	}
}

// extractClientIDFromEvent extracts the client_id from event data
func extractClientIDFromEvent(data interface{}) string {
	if data == nil {
		return ""
	}

	// Try to get client_id from map
	if m, ok := data.(map[string]interface{}); ok {
		if clientID, ok := m["client_id"].(string); ok {
			return clientID
		}
	}

	return ""
}

// buildCertInfoFromEvent builds CertificateInfo from event data
func buildCertInfoFromEvent(data interface{}) *lcmV1.CertificateInfo {
	if data == nil {
		return nil
	}

	m, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}

	info := &lcmV1.CertificateInfo{}

	if v, ok := m["common_name"].(string); ok {
		info.CommonName = v
		info.Name = v
	}
	if v, ok := m["serial_number"].(string); ok {
		info.SerialNumber = v
	}
	if v, ok := m["issuer_name"].(string); ok {
		info.IssuerName = v
	}
	if dnsNames, ok := m["dns_names"].([]interface{}); ok {
		for _, d := range dnsNames {
			if s, ok := d.(string); ok {
				info.DnsNames = append(info.DnsNames, s)
			}
		}
	}

	return info
}

// mapCertStatusToClientStatus maps MtlsCertificateStatus to ClientCertificateStatus
func mapCertStatusToClientStatus(status lcmV1.MtlsCertificateStatus) lcmV1.ClientCertificateStatus {
	switch status {
	case lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE:
		return lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED
	case lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_REVOKED:
		return lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED
	case lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_EXPIRED:
		return lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED
	default:
		return lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_UNKNOWN
	}
}

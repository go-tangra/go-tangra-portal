package middleware

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

// Use the shared ClientInfo type from pkg/client
type ClientInfo = client.ClientInfo

// MTLSMiddleware creates a mutual TLS authentication middleware
func MTLSMiddleware(logger log.Logger) middleware.Middleware {
	l := log.NewHelper(log.With(logger, "module", "middleware/mtls"))

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			// Get the transport info to determine the operation
			if tr, ok := transport.FromServerContext(ctx); ok {
				operation := tr.Operation()

				// Extract peer information from gRPC context
				p, ok := peer.FromContext(ctx)
				if !ok {
					l.Error("Failed to get peer information from context")
					return nil, status.Error(codes.Unauthenticated, "failed to get peer information")
				}

				// Extract client certificate information if available
				clientInfo := extractClientInfo(p, l)

				// Skip mTLS for public endpoints
				if isPublicEndpoint(operation) {
					l.Debugf("Skipping mTLS for public endpoint: %s", operation)
					// Still add client info to context even for public endpoints (may be nil)
					ctx = context.WithValue(ctx, client.ClientInfoKey, clientInfo)
					return handler(ctx, req)
				}

				l.Debugf("Validating client certificate for operation: %s", operation)

				// Validate client certificate for protected endpoints
				if clientInfo == nil || !clientInfo.IsAuthenticated {
					l.Error("Client certificate validation failed: no valid certificate")
					return nil, status.Error(codes.Unauthenticated, "client certificate required for this endpoint")
				}

				l.Debugf("Client certificate validated successfully for operation: %s (CN: %s)", operation, clientInfo.CommonName)

				// Add client info to context
				ctx = context.WithValue(ctx, client.ClientInfoKey, clientInfo)
			}

			return handler(ctx, req)
		}
	}
}

// isPublicEndpoint checks if the given operation is a public endpoint that doesn't require mTLS
func isPublicEndpoint(operation string) bool {
	publicEndpoints := []string{
		"/lcm.service.v1.LcmClientService/DownloadClientCertificate",
		"/lcm.service.v1.LcmClientService/GetRequestStatus",
		"/lcm.service.v1.LcmClientService/RegisterLcmClient",
		"/lcm.service.v1.ClientService/Register",
		"/lcm.service.v1.ClientService/DownloadClientCert",
		"/lcm.service.v1.SystemService/HealthCheck",
	}

	return slices.Contains(publicEndpoints, operation)
}

// extractClientInfo extracts and validates client certificate information from peer
func extractClientInfo(p *peer.Peer, l *log.Helper) *ClientInfo {
	// Check if the connection has TLS info
	if p.AuthInfo == nil {
		l.Debug("No TLS authentication info available")
		return nil
	}

	// Cast to TLS credentials to access certificate information
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		l.Debug("Failed to cast to TLS credentials")
		return nil
	}

	// Check if client certificates are present
	if len(tlsInfo.State.PeerCertificates) == 0 {
		l.Debug("No client certificates provided")
		return nil
	}

	// Get the first (leaf) certificate
	clientCert := tlsInfo.State.PeerCertificates[0]

	// Create client info struct
	clientInfo := &ClientInfo{
		Certificate:     clientCert,
		Subject:         clientCert.Subject.String(),
		Issuer:          clientCert.Issuer.String(),
		SerialNumber:    clientCert.SerialNumber.String(),
		CommonName:      clientCert.Subject.CommonName,
		Organizations:   clientCert.Subject.Organization,
		NotBefore:       clientCert.NotBefore,
		NotAfter:        clientCert.NotAfter,
		IsAuthenticated: false, // Will be set to true after validation
	}

	// Log certificate information for debugging
	l.Debugf("Client certificate Subject: %s", clientInfo.Subject)
	l.Debugf("Client certificate Issuer: %s", clientInfo.Issuer)
	l.Debugf("Client certificate Serial: %s", clientInfo.SerialNumber)

	// Validate certificate
	if err := validateCertificateValidity(clientCert); err != nil {
		l.Debugf("Certificate validity check failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	if err := validateCertificateIssuer(clientCert); err != nil {
		l.Debugf("Certificate issuer validation failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	// Mark as authenticated if all validations pass
	clientInfo.IsAuthenticated = true
	l.Debugf("Client certificate validation successful")

	return clientInfo
}

// GetClientInfoFromContext extracts client information from the request context
// This function now delegates to the shared client package
func GetClientInfoFromContext(ctx context.Context) (*ClientInfo, bool) {
	return client.GetClientInfoFromContext(ctx)
}

// GetClientCertificateFromContext extracts the client certificate from the request context
// This function now delegates to the shared client package
func GetClientCertificateFromContext(ctx context.Context) (*x509.Certificate, bool) {
	return client.GetClientCertificateFromContext(ctx)
}

// IsClientAuthenticated checks if the client is authenticated via mTLS
// This function now delegates to the shared client package
func IsClientAuthenticated(ctx context.Context) bool {
	return client.IsClientAuthenticated(ctx)
}

// validateCertificateValidity checks if the certificate is currently valid
func validateCertificateValidity(cert *x509.Certificate) error {
	now := time.Now()
	if cert.NotBefore.After(now) {
		return fmt.Errorf("certificate not yet valid (NotBefore: %v)", cert.NotBefore)
	}
	if cert.NotAfter.Before(now) {
		return fmt.Errorf("certificate expired (NotAfter: %v)", cert.NotAfter)
	}
	return nil
}

// validateCertificateIssuer checks if the certificate was issued by our CA
func validateCertificateIssuer(cert *x509.Certificate) error {
	// Check if the issuer contains "LCM" which should be present in our CA
	issuerStr := cert.Issuer.String()
	if issuerStr == "" {
		return fmt.Errorf("certificate has no issuer information")
	}

	// Simple check - in production you might want to verify against the actual CA certificate
	expectedOrgUnits := []string{"LCM Certificate Authority", "LCM"}
	for _, ou := range cert.Issuer.OrganizationalUnit {
		if slices.Contains(expectedOrgUnits, ou) {
			return nil // Valid issuer
		}
	}

	// Check organization as well
	if slices.Contains(cert.Issuer.Organization, "LCM") {
		return nil // Valid issuer
	}

	return fmt.Errorf("certificate not issued by trusted CA (issuer: %s)", issuerStr)
}

// ExtractClientCertificate extracts the client certificate from the context
// This function is now implemented using the mTLS middleware context
func ExtractClientCertificate(ctx context.Context) (*x509.Certificate, error) {
	if cert, ok := GetClientCertificateFromContext(ctx); ok {
		return cert, nil
	}
	return nil, errors.New(401, "NO_CLIENT_CERT", "no client certificate found in context")
}

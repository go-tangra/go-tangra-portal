package data

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

// LcmClients holds all LCM service gRPC clients
type LcmClients struct {
	conn *grpc.ClientConn
	log  *log.Helper

	ClientService                lcmV1.LcmClientServiceClient
	IssuerService                lcmV1.LcmIssuerServiceClient
	CertificateService           lcmV1.LcmCertificateJobServiceClient
	TenantSecretService          lcmV1.TenantSecretServiceClient
	AuditLogService              lcmV1.AuditLogServiceClient
	MtlsCertService              lcmV1.LcmMtlsCertificateServiceClient
	MtlsCertRequestService       lcmV1.LcmMtlsCertificateRequestServiceClient
	CertificatePermissionService lcmV1.CertificatePermissionServiceClient
	StatisticsService            lcmV1.LcmStatisticsServiceClient
}

// NewLcmClients creates a new LcmClients instance
func NewLcmClients(ctx *bootstrap.Context) (*LcmClients, func(), error) {
	l := ctx.NewLoggerHelper("lcm/client/admin-service")

	// Get LCM endpoint from environment variable, fallback to default
	endpoint := os.Getenv("LCM_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:9100" // Default LCM gRPC endpoint
	}

	l.Infof("Connecting to LCM service at: %s", endpoint)

	// Load TLS credentials for mTLS connection to LCM service
	creds, err := loadLcmClientTLSCredentials(l)
	if err != nil {
		l.Warnf("Failed to load TLS credentials, LCM service will not be available: %v", err)
		return nil, func() {}, nil // Return nil clients, service will be unavailable
	}

	// Configure connection parameters for automatic reconnection
	connectParams := grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  1 * time.Second,
			Multiplier: 1.5,
			Jitter:     0.2,
			MaxDelay:   30 * time.Second,
		},
		MinConnectTimeout: 5 * time.Second,
	}

	// Configure keepalive to detect dead connections
	keepaliveParams := keepalive.ClientParameters{
		Time:                10 * time.Second, // Send pings every 10 seconds if no activity
		Timeout:             5 * time.Second,  // Wait 5 seconds for ping ack before considering connection dead
		PermitWithoutStream: true,             // Send pings even without active streams
	}

	// Create gRPC connection with TLS and reconnection settings
	conn, err := grpc.NewClient(
		endpoint,
		grpc.WithTransportCredentials(creds),
		grpc.WithConnectParams(connectParams),
		grpc.WithKeepaliveParams(keepaliveParams),
		grpc.WithDefaultServiceConfig(`{
			"loadBalancingConfig": [{"round_robin":{}}],
			"methodConfig": [{
				"name": [{"service": ""}],
				"waitForReady": true,
				"retryPolicy": {
					"MaxAttempts": 3,
					"InitialBackoff": "0.5s",
					"MaxBackoff": "5s",
					"BackoffMultiplier": 2,
					"RetryableStatusCodes": ["UNAVAILABLE", "RESOURCE_EXHAUSTED"]
				}
			}]
		}`),
	)
	if err != nil {
		l.Errorf("Failed to connect to LCM service: %v", err)
		return nil, func() {}, err
	}

	clients := &LcmClients{
		conn:                         conn,
		log:                          l,
		ClientService:                lcmV1.NewLcmClientServiceClient(conn),
		IssuerService:                lcmV1.NewLcmIssuerServiceClient(conn),
		CertificateService:           lcmV1.NewLcmCertificateJobServiceClient(conn),
		TenantSecretService:          lcmV1.NewTenantSecretServiceClient(conn),
		AuditLogService:              lcmV1.NewAuditLogServiceClient(conn),
		MtlsCertService:              lcmV1.NewLcmMtlsCertificateServiceClient(conn),
		MtlsCertRequestService:       lcmV1.NewLcmMtlsCertificateRequestServiceClient(conn),
		CertificatePermissionService: lcmV1.NewCertificatePermissionServiceClient(conn),
		StatisticsService:            lcmV1.NewLcmStatisticsServiceClient(conn),
	}

	cleanup := func() {
		if err := conn.Close(); err != nil {
			l.Errorf("Failed to close LCM connection: %v", err)
		}
	}

	l.Info("LCM clients initialized successfully")

	return clients, cleanup, nil
}

// IsConnected checks if the LCM client is connected
func (c *LcmClients) IsConnected(ctx context.Context) bool {
	if c == nil || c.conn == nil {
		return false
	}
	return c.conn.GetState().String() == "READY"
}

// loadLcmClientTLSCredentials loads TLS credentials for connecting to LCM service
func loadLcmClientTLSCredentials(l *log.Helper) (credentials.TransportCredentials, error) {
	// Get certificate paths from environment or use defaults
	caCertPath := os.Getenv("LCM_CA_CERT_PATH")
	if caCertPath == "" {
		caCertPath = "./data/ca/ca.crt"
	}
	clientCertPath := os.Getenv("LCM_CLIENT_CERT_PATH")
	if clientCertPath == "" {
		clientCertPath = "./data/admin/admin.crt"
	}
	clientKeyPath := os.Getenv("LCM_CLIENT_KEY_PATH")
	if clientKeyPath == "" {
		clientKeyPath = "./data/admin/admin.key"
	}

	// Load CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		l.Errorf("Failed to read CA cert from %s: %v", caCertPath, err)
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		l.Errorf("Failed to parse CA cert from %s", caCertPath)
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		l.Errorf("Failed to load client cert/key from %s, %s: %v", clientCertPath, clientKeyPath, err)
		return nil, err
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "localhost", // Must match a SAN in the server certificate
		MinVersion:   tls.VersionTLS12,
	}

	l.Infof("Loaded TLS credentials: CA=%s, Cert=%s", caCertPath, clientCertPath)

	return credentials.NewTLS(tlsConfig), nil
}

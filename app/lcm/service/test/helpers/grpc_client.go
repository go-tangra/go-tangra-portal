package helpers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
)

// GRPCClients holds all LCM gRPC service clients
type GRPCClients struct {
	conn           *grpc.ClientConn
	System         lcmV1.SystemServiceClient
	LcmClient      lcmV1.LcmClientServiceClient
	Issuer         lcmV1.LcmIssuerServiceClient
	CertificateJob lcmV1.LcmCertificateJobServiceClient
	TenantSecret   lcmV1.TenantSecretServiceClient
	AuditLog       lcmV1.AuditLogServiceClient
}

// ClientConfig holds configuration for creating gRPC clients
type ClientConfig struct {
	ServerAddr string
	CertFile   string // Client certificate for mTLS (optional for registration)
	KeyFile    string // Client key for mTLS (optional for registration)
	CAFile     string // CA certificate for server verification
	Timeout    time.Duration
}

// NewGRPCClients creates gRPC clients for all LCM services
func NewGRPCClients(cfg *ClientConfig) (*GRPCClients, error) {
	// Load CA certificate
	caCert, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	// Load client certificate if provided (for mTLS)
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Create connection
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.ServerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	return &GRPCClients{
		conn:           conn,
		System:         lcmV1.NewSystemServiceClient(conn),
		LcmClient:      lcmV1.NewLcmClientServiceClient(conn),
		Issuer:         lcmV1.NewLcmIssuerServiceClient(conn),
		CertificateJob: lcmV1.NewLcmCertificateJobServiceClient(conn),
		TenantSecret:   lcmV1.NewTenantSecretServiceClient(conn),
		AuditLog:       lcmV1.NewAuditLogServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection
func (c *GRPCClients) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// HealthCheck performs a health check on the LCM service
func (c *GRPCClients) HealthCheck(ctx context.Context) error {
	_, err := c.System.HealthCheck(ctx, &lcmV1.HealthCheckRequest{})
	return err
}

// WaitForServer waits for the server to become healthy
func (c *GRPCClients) WaitForServer(ctx context.Context, maxRetries int, retryInterval time.Duration) error {
	for i := 0; i < maxRetries; i++ {
		if err := c.HealthCheck(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryInterval):
			continue
		}
	}
	return fmt.Errorf("server not healthy after %d retries", maxRetries)
}

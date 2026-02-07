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

	deployerV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/deployer/service/v1"
)

// DeployerClients holds all Deployer service gRPC clients
type DeployerClients struct {
	conn *grpc.ClientConn
	log  *log.Helper

	TargetService        deployerV1.DeploymentTargetServiceClient
	ConfigurationService deployerV1.TargetConfigurationServiceClient
	JobService           deployerV1.DeploymentJobServiceClient
	DeploymentService    deployerV1.DeploymentServiceClient
	StatisticsService    deployerV1.DeployerStatisticsServiceClient
}

// NewDeployerClients creates a new DeployerClients instance
func NewDeployerClients(ctx *bootstrap.Context) (*DeployerClients, func(), error) {
	l := ctx.NewLoggerHelper("deployer/client/admin-service")

	// Get Deployer endpoint from environment variable, fallback to default
	endpoint := os.Getenv("DEPLOYER_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:9200" // Default Deployer gRPC endpoint
	}

	l.Infof("Connecting to Deployer service at: %s", endpoint)

	// Load TLS credentials for mTLS connection to Deployer service
	creds, err := loadDeployerClientTLSCredentials(l)
	if err != nil {
		l.Warnf("Failed to load TLS credentials, Deployer service will not be available: %v", err)
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
	// Note: gRPC servers enforce a minimum ping interval (default 5 minutes)
	// Setting Time too low causes ENHANCE_YOUR_CALM errors
	keepaliveParams := keepalive.ClientParameters{
		Time:                5 * time.Minute,  // Send pings every 5 minutes if no activity
		Timeout:             20 * time.Second, // Wait 20 seconds for ping ack before considering connection dead
		PermitWithoutStream: false,            // Don't send pings without active streams
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
		l.Errorf("Failed to connect to Deployer service: %v", err)
		return nil, func() {}, err
	}

	clients := &DeployerClients{
		conn:                 conn,
		log:                  l,
		TargetService:        deployerV1.NewDeploymentTargetServiceClient(conn),
		ConfigurationService: deployerV1.NewTargetConfigurationServiceClient(conn),
		JobService:           deployerV1.NewDeploymentJobServiceClient(conn),
		DeploymentService:    deployerV1.NewDeploymentServiceClient(conn),
		StatisticsService:    deployerV1.NewDeployerStatisticsServiceClient(conn),
	}

	cleanup := func() {
		if err := conn.Close(); err != nil {
			l.Errorf("Failed to close Deployer connection: %v", err)
		}
	}

	l.Info("Deployer clients initialized successfully")

	return clients, cleanup, nil
}

// IsConnected checks if the Deployer client is connected
func (c *DeployerClients) IsConnected(ctx context.Context) bool {
	if c == nil || c.conn == nil {
		return false
	}
	return c.conn.GetState().String() == "READY"
}

// loadDeployerClientTLSCredentials loads TLS credentials for connecting to Deployer service
func loadDeployerClientTLSCredentials(l *log.Helper) (credentials.TransportCredentials, error) {
	// Get certificate paths from environment or use defaults
	caCertPath := os.Getenv("DEPLOYER_CA_CERT_PATH")
	if caCertPath == "" {
		caCertPath = "./data/ca/ca.crt"
	}
	clientCertPath := os.Getenv("DEPLOYER_CLIENT_CERT_PATH")
	if clientCertPath == "" {
		clientCertPath = "./data/deployer/deployer.crt"
	}
	clientKeyPath := os.Getenv("DEPLOYER_CLIENT_KEY_PATH")
	if clientKeyPath == "" {
		clientKeyPath = "./data/deployer/deployer.key"
	}

	// Get server name for TLS verification - must match a SAN in the server certificate
	// Default to deployer-service which should be in the server cert's SANs
	serverName := os.Getenv("DEPLOYER_SERVER_NAME")
	if serverName == "" {
		serverName = "deployer-service"
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
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}

	l.Infof("Loaded TLS credentials: CA=%s, Cert=%s, ServerName=%s", caCertPath, clientCertPath, serverName)

	return credentials.NewTLS(tlsConfig), nil
}

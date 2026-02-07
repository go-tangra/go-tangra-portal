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

	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

// IpamClients holds all IPAM service gRPC clients
type IpamClients struct {
	conn *grpc.ClientConn
	log  *log.Helper

	SystemService ipamV1.SystemServiceClient
}

// NewIpamClients creates a new IpamClients instance
func NewIpamClients(ctx *bootstrap.Context) (*IpamClients, func(), error) {
	l := ctx.NewLoggerHelper("ipam/client/admin-service")

	// Get IPAM endpoint from environment variable, fallback to default
	endpoint := os.Getenv("IPAM_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:9400" // Default IPAM gRPC endpoint
	}

	l.Infof("Connecting to IPAM service at: %s", endpoint)

	// Load TLS credentials for mTLS connection to IPAM service
	creds, err := loadIpamClientTLSCredentials(l)
	if err != nil {
		l.Warnf("Failed to load TLS credentials, IPAM service will not be available: %v", err)
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
		Time:                5 * time.Minute,
		Timeout:             20 * time.Second,
		PermitWithoutStream: false,
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
		l.Errorf("Failed to connect to IPAM service: %v", err)
		return nil, func() {}, err
	}

	clients := &IpamClients{
		conn:          conn,
		log:           l,
		SystemService: ipamV1.NewSystemServiceClient(conn),
	}

	cleanup := func() {
		if err := conn.Close(); err != nil {
			l.Errorf("Failed to close IPAM connection: %v", err)
		}
	}

	l.Info("IPAM clients initialized successfully")

	return clients, cleanup, nil
}

// IsConnected checks if the IPAM client is connected
func (c *IpamClients) IsConnected(ctx context.Context) bool {
	if c == nil || c.conn == nil {
		return false
	}
	return c.conn.GetState().String() == "READY"
}

// loadIpamClientTLSCredentials loads TLS credentials for connecting to IPAM service
func loadIpamClientTLSCredentials(l *log.Helper) (credentials.TransportCredentials, error) {
	caCertPath := os.Getenv("IPAM_CA_CERT_PATH")
	if caCertPath == "" {
		caCertPath = "./data/ca/ca.crt"
	}
	clientCertPath := os.Getenv("IPAM_CLIENT_CERT_PATH")
	if clientCertPath == "" {
		clientCertPath = "./data/ipam/ipam.crt"
	}
	clientKeyPath := os.Getenv("IPAM_CLIENT_KEY_PATH")
	if clientKeyPath == "" {
		clientKeyPath = "./data/ipam/ipam.key"
	}

	serverName := os.Getenv("IPAM_SERVER_NAME")
	if serverName == "" {
		serverName = "ipam-service"
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

package data

import (
	"context"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/keepalive"

	paperlessV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/paperless/service/v1"
)

// PaperlessClients holds all Paperless service gRPC clients
type PaperlessClients struct {
	conn *grpc.ClientConn
	log  *log.Helper

	StatisticsService paperlessV1.PaperlessStatisticsServiceClient
}

// NewPaperlessClients creates a new PaperlessClients instance
func NewPaperlessClients(ctx *bootstrap.Context) (*PaperlessClients, func(), error) {
	l := ctx.NewLoggerHelper("paperless/client/admin-service")

	// Get Paperless endpoint from environment variable, fallback to default
	endpoint := os.Getenv("PAPERLESS_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:9500" // Default Paperless gRPC endpoint
	}

	l.Infof("Connecting to Paperless service at: %s", endpoint)

	// Load TLS credentials for mTLS connection to Paperless service
	creds, err := loadAdminClientTLS("paperless-service", l)
	if err != nil {
		l.Warnf("Failed to load TLS credentials, Paperless service will not be available: %v", err)
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
		l.Errorf("Failed to connect to Paperless service: %v", err)
		return nil, func() {}, err
	}

	clients := &PaperlessClients{
		conn:              conn,
		log:               l,
		StatisticsService: paperlessV1.NewPaperlessStatisticsServiceClient(conn),
	}

	cleanup := func() {
		if err := conn.Close(); err != nil {
			l.Errorf("Failed to close Paperless connection: %v", err)
		}
	}

	l.Info("Paperless clients initialized successfully")

	return clients, cleanup, nil
}

// IsConnected checks if the Paperless client is connected
func (c *PaperlessClients) IsConnected(ctx context.Context) bool {
	if c == nil || c.conn == nil {
		return false
	}
	return c.conn.GetState().String() == "READY"
}


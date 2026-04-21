package data

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/keepalive"

	notificationv1 "buf.build/gen/go/go-tangra/notification/protocolbuffers/go/notification/service/v1"
	notificationgrpc "buf.build/gen/go/go-tangra/notification/grpc/go/notification/service/v1/servicev1grpc"
)

// NotificationClient wraps the gRPC stubs for the notification-service.
// It is safe to hold a nil value if the service is unreachable at startup —
// every exported method handles that case gracefully so admin-service can
// continue serving requests without email delivery.
type NotificationClient struct {
	conn *grpc.ClientConn
	log  *log.Helper

	NotificationService notificationgrpc.NotificationServiceClient
	TemplateService     notificationgrpc.NotificationTemplateServiceClient
	ChannelService      notificationgrpc.NotificationChannelServiceClient
}

// NewNotificationClient dials notification-service over mTLS using the same
// pattern as the other module clients (lcm, paperless, ipam, deployer).
func NewNotificationClient(ctx *bootstrap.Context) (*NotificationClient, func(), error) {
	l := ctx.NewLoggerHelper("notification/client/admin-service")

	endpoint := os.Getenv("NOTIFICATION_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:9800"
	}

	l.Infof("Connecting to Notification service at: %s", endpoint)

	creds, err := loadAdminClientTLS("notification-service", l)
	if err != nil {
		l.Warnf("Failed to load TLS credentials, Notification service will not be available: %v", err)
		return &NotificationClient{log: l}, func() {}, nil
	}

	conn, err := grpc.NewClient(
		endpoint,
		grpc.WithTransportCredentials(creds),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   30 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                5 * time.Minute,
			Timeout:             20 * time.Second,
			PermitWithoutStream: false,
		}),
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
		l.Errorf("Failed to connect to Notification service: %v", err)
		return &NotificationClient{log: l}, func() {}, nil
	}

	client := &NotificationClient{
		conn:                conn,
		log:                 l,
		NotificationService: notificationgrpc.NewNotificationServiceClient(conn),
		TemplateService:     notificationgrpc.NewNotificationTemplateServiceClient(conn),
		ChannelService:      notificationgrpc.NewNotificationChannelServiceClient(conn),
	}

	cleanup := func() {
		if err := conn.Close(); err != nil {
			l.Errorf("Failed to close Notification connection: %v", err)
		}
	}

	l.Info("Notification client initialized successfully")
	return client, cleanup, nil
}

// SendNotification sends a templated notification. Returns (nil, nil) if the
// client wasn't able to connect at startup — callers should treat email
// delivery as best-effort.
func (c *NotificationClient) SendNotification(ctx context.Context, templateID, recipient string, variables map[string]string) (*notificationv1.NotificationLog, error) {
	if c == nil || c.NotificationService == nil {
		return nil, nil
	}
	resp, err := c.NotificationService.SendNotification(ctx, &notificationv1.SendNotificationRequest{
		TemplateId: templateID,
		Recipient:  recipient,
		Variables:  variables,
	})
	if err != nil {
		return nil, fmt.Errorf("send notification: %w", err)
	}
	return resp.GetNotification(), nil
}

// FindTemplateByName returns nil, nil when no template matches.
func (c *NotificationClient) FindTemplateByName(ctx context.Context, name string) (*notificationv1.NotificationTemplate, error) {
	if c == nil || c.TemplateService == nil {
		return nil, nil
	}
	resp, err := c.TemplateService.ListTemplates(ctx, &notificationv1.ListTemplatesRequest{})
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	for _, tmpl := range resp.GetTemplates() {
		if tmpl.GetName() == name {
			return tmpl, nil
		}
	}
	return nil, nil
}

// FindChannelByName returns the channel ID, or empty string + error if absent.
func (c *NotificationClient) FindChannelByName(ctx context.Context, name string) (string, error) {
	if c == nil || c.ChannelService == nil {
		return "", fmt.Errorf("notification client unavailable")
	}
	resp, err := c.ChannelService.ListChannels(ctx, &notificationv1.ListChannelsRequest{})
	if err != nil {
		return "", fmt.Errorf("list channels: %w", err)
	}
	for _, ch := range resp.GetChannels() {
		if ch.GetName() == name {
			return ch.GetId(), nil
		}
	}
	return "", fmt.Errorf("channel %q not found", name)
}

// CreateTemplate proxies template creation.
func (c *NotificationClient) CreateTemplate(ctx context.Context, req *notificationv1.CreateTemplateRequest) (*notificationv1.NotificationTemplate, error) {
	if c == nil || c.TemplateService == nil {
		return nil, fmt.Errorf("notification client unavailable")
	}
	resp, err := c.TemplateService.CreateTemplate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create template: %w", err)
	}
	return resp.GetTemplate(), nil
}

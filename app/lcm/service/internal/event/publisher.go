package event

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
)

// Publisher handles event publishing for LCM operations
type Publisher struct {
	log         *log.Helper
	redisClient *redis.Client
	config      *conf.EventConfig
	topicPrefix string
}

// NewPublisher creates a new event publisher
func NewPublisher(ctx *bootstrap.Context, redisClient *redis.Client) *Publisher {
	l := ctx.NewLoggerHelper("event/publisher/lcm-service")

	// Get event config from LCM config
	var eventConfig *conf.EventConfig
	var topicPrefix string = "lcm"

	customConfig, ok := ctx.GetCustomConfig("lcm")
	if ok {
		lcmConfig, ok := customConfig.(*conf.LCM)
		if ok && lcmConfig != nil {
			eventConfig = lcmConfig.GetEvents()
			if eventConfig != nil && eventConfig.GetTopicPrefix() != "" {
				topicPrefix = eventConfig.GetTopicPrefix()
			}
		}
	}

	return &Publisher{
		log:         l,
		redisClient: redisClient,
		config:      eventConfig,
		topicPrefix: topicPrefix,
	}
}

// IsEnabled returns true if event publishing is enabled
func (p *Publisher) IsEnabled() bool {
	if p.config == nil {
		return false
	}
	return p.config.GetEnabled()
}

// Publish publishes an event to the specified topic
func (p *Publisher) Publish(ctx context.Context, topic string, data any) error {
	if !p.IsEnabled() {
		return nil
	}

	if p.redisClient == nil {
		p.log.Warn("Redis client is nil, skipping event publish")
		return nil
	}

	// Create the full event envelope
	event := LCMEvent{
		ID:        uuid.New().String(),
		Type:      topic,
		Source:    EventSource,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	// Extract tenant ID from the data if possible
	if tenantData, ok := data.(interface{ GetTenantID() uint32 }); ok {
		event.TenantID = tenantData.GetTenantID()
	}

	// Serialize to JSON
	payload, err := json.Marshal(event)
	if err != nil {
		p.log.Errorf("Failed to marshal event: %v", err)
		return err
	}

	// Publish to Redis channel
	fullTopic := p.topicPrefix + "." + topic
	if err := p.redisClient.Publish(ctx, fullTopic, payload).Err(); err != nil {
		p.log.Errorf("Failed to publish event to %s: %v", fullTopic, err)
		return err
	}

	p.log.Debugf("Published event to %s: %s", fullTopic, event.ID)
	return nil
}

// PublishClientRegistered publishes a client registered event
func (p *Publisher) PublishClientRegistered(ctx context.Context, event *ClientRegisteredEvent) error {
	return p.Publish(ctx, TopicClientRegistered, event)
}

// PublishClientUpdated publishes a client updated event
func (p *Publisher) PublishClientUpdated(ctx context.Context, event *ClientRegisteredEvent) error {
	return p.Publish(ctx, TopicClientUpdated, event)
}

// PublishCertificateRequested publishes a certificate requested event
func (p *Publisher) PublishCertificateRequested(ctx context.Context, event *CertificateRequestedEvent) error {
	return p.Publish(ctx, TopicCertificateRequested, event)
}

// PublishCertificateProcessing publishes a certificate processing event
func (p *Publisher) PublishCertificateProcessing(ctx context.Context, event *CertificateRequestedEvent) error {
	return p.Publish(ctx, TopicCertificateProcessing, event)
}

// PublishCertificateIssued publishes a certificate issued event
func (p *Publisher) PublishCertificateIssued(ctx context.Context, event *CertificateIssuedEvent) error {
	return p.Publish(ctx, TopicCertificateIssued, event)
}

// PublishCertificateFailed publishes a certificate failed event
func (p *Publisher) PublishCertificateFailed(ctx context.Context, event *CertificateFailedEvent) error {
	return p.Publish(ctx, TopicCertificateFailed, event)
}

// PublishCertificateCancelled publishes a certificate cancelled event
func (p *Publisher) PublishCertificateCancelled(ctx context.Context, event *CertificateCancelledEvent) error {
	return p.Publish(ctx, TopicCertificateCancelled, event)
}

// PublishRenewalScheduled publishes a renewal scheduled event
func (p *Publisher) PublishRenewalScheduled(ctx context.Context, event *RenewalScheduledEvent) error {
	return p.Publish(ctx, TopicRenewalScheduled, event)
}

// PublishRenewalStarted publishes a renewal started event
func (p *Publisher) PublishRenewalStarted(ctx context.Context, event *RenewalScheduledEvent) error {
	return p.Publish(ctx, TopicRenewalStarted, event)
}

// PublishRenewalCompleted publishes a renewal completed event
func (p *Publisher) PublishRenewalCompleted(ctx context.Context, event *RenewalCompletedEvent) error {
	return p.Publish(ctx, TopicRenewalCompleted, event)
}

// PublishRenewalFailed publishes a renewal failed event
func (p *Publisher) PublishRenewalFailed(ctx context.Context, event *RenewalFailedEvent) error {
	return p.Publish(ctx, TopicRenewalFailed, event)
}

// PublishIssuerCreated publishes an issuer created event
func (p *Publisher) PublishIssuerCreated(ctx context.Context, event *IssuerCreatedEvent) error {
	return p.Publish(ctx, TopicIssuerCreated, event)
}

// PublishIssuerUpdated publishes an issuer updated event
func (p *Publisher) PublishIssuerUpdated(ctx context.Context, event *IssuerUpdatedEvent) error {
	return p.Publish(ctx, TopicIssuerUpdated, event)
}

// PublishIssuerDeleted publishes an issuer deleted event
func (p *Publisher) PublishIssuerDeleted(ctx context.Context, event *IssuerDeletedEvent) error {
	return p.Publish(ctx, TopicIssuerDeleted, event)
}

// PublishTenantSecretCreated publishes a tenant secret created event
func (p *Publisher) PublishTenantSecretCreated(ctx context.Context, event *TenantSecretCreatedEvent) error {
	return p.Publish(ctx, TopicTenantSecretCreated, event)
}

// PublishTenantSecretRotated publishes a tenant secret rotated event
func (p *Publisher) PublishTenantSecretRotated(ctx context.Context, event *TenantSecretRotatedEvent) error {
	return p.Publish(ctx, TopicTenantSecretRotated, event)
}

// PublishTenantSecretDeleted publishes a tenant secret deleted event
func (p *Publisher) PublishTenantSecretDeleted(ctx context.Context, event *TenantSecretDeletedEvent) error {
	return p.Publish(ctx, TopicTenantSecretDeleted, event)
}

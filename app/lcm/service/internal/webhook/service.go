package webhook

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/redis/go-redis/v9"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
)

// Service orchestrates the webhook notification system
type Service struct {
	log         *log.Helper
	config      *conf.WebhookConfig
	client      *Client
	subscriber  *Subscriber
	redisClient *redis.Client

	running     bool
	runningLock sync.Mutex
}

// NewService creates a new webhook service
func NewService(ctx *bootstrap.Context, redisClient *redis.Client) (*Service, error) {
	l := ctx.NewLoggerHelper("webhook/service")

	// Get webhook config from LCM config
	var webhookConfig *conf.WebhookConfig
	var topicPrefix string = "lcm"

	customConfig, ok := ctx.GetCustomConfig("lcm")
	if ok {
		lcmConfig, ok := customConfig.(*conf.LCM)
		if ok && lcmConfig != nil {
			webhookConfig = lcmConfig.GetWebhooks()

			// Get event topic prefix
			if eventConfig := lcmConfig.GetEvents(); eventConfig != nil && eventConfig.GetTopicPrefix() != "" {
				topicPrefix = eventConfig.GetTopicPrefix()
			}
		}
	}

	if webhookConfig == nil {
		l.Info("Webhook configuration not found, service disabled")
		return &Service{
			log:    l,
			config: nil,
		}, nil
	}

	if !webhookConfig.GetEnabled() {
		l.Info("Webhook service is disabled in configuration")
		return &Service{
			log:    l,
			config: webhookConfig,
		}, nil
	}

	client := NewClient(webhookConfig, l)
	subscriber := NewSubscriber(redisClient, client, webhookConfig, topicPrefix, l)

	return &Service{
		log:         l,
		config:      webhookConfig,
		client:      client,
		subscriber:  subscriber,
		redisClient: redisClient,
	}, nil
}

// Start starts the webhook service
func (s *Service) Start() error {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if s.running {
		return nil
	}

	if s.config == nil || !s.config.GetEnabled() {
		s.log.Info("Webhook service is disabled")
		return nil
	}

	if s.subscriber == nil {
		return fmt.Errorf("webhook subscriber not initialized")
	}

	if err := s.subscriber.Start(context.Background()); err != nil {
		return fmt.Errorf("failed to start webhook subscriber: %w", err)
	}

	s.running = true
	s.log.Info("Webhook service started")
	return nil
}

// Stop stops the webhook service
func (s *Service) Stop() error {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if !s.running {
		return nil
	}

	if s.subscriber != nil {
		if err := s.subscriber.Stop(); err != nil {
			s.log.Warnf("Error stopping webhook subscriber: %v", err)
		}
	}

	s.running = false
	s.log.Info("Webhook service stopped")
	return nil
}

// IsRunning returns whether the service is running
func (s *Service) IsRunning() bool {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()
	return s.running
}

// IsEnabled returns whether webhooks are enabled
func (s *Service) IsEnabled() bool {
	return s.config != nil && s.config.GetEnabled()
}

// GetEndpointCount returns the number of configured endpoints
func (s *Service) GetEndpointCount() int {
	if s.config == nil {
		return 0
	}
	return len(s.config.GetEndpoints())
}

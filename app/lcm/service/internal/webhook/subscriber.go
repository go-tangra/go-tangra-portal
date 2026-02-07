package webhook

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/event"
)

// Subscriber listens to Redis pub/sub events and forwards them to webhooks
type Subscriber struct {
	log         *log.Helper
	redisClient *redis.Client
	client      *Client
	config      *conf.WebhookConfig
	topicPrefix string

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewSubscriber creates a new webhook subscriber
func NewSubscriber(
	redisClient *redis.Client,
	client *Client,
	config *conf.WebhookConfig,
	topicPrefix string,
	logger *log.Helper,
) *Subscriber {
	if topicPrefix == "" {
		topicPrefix = "lcm"
	}

	return &Subscriber{
		log:         logger,
		redisClient: redisClient,
		client:      client,
		config:      config,
		topicPrefix: topicPrefix,
	}
}

// Start begins subscribing to Redis pub/sub events
func (s *Subscriber) Start(ctx context.Context) error {
	if s.redisClient == nil {
		s.log.Warn("Redis client is nil, webhook subscriber not started")
		return nil
	}

	s.stopCh = make(chan struct{})

	// Subscribe to all LCM event topics
	patterns := []string{
		s.topicPrefix + ".certificate.*",
		s.topicPrefix + ".renewal.*",
	}

	pubsub := s.redisClient.PSubscribe(ctx, patterns...)

	// Start worker goroutines
	workerCount := int(s.config.GetWorkerCount())
	if workerCount <= 0 {
		workerCount = 2
	}

	// Channel for distributing messages to workers
	msgChan := make(chan *redis.Message, workerCount*10)

	// Start workers
	for i := 0; i < workerCount; i++ {
		s.wg.Add(1)
		go s.worker(ctx, i, msgChan)
	}

	// Start message receiver
	s.wg.Add(1)
	go s.receiver(ctx, pubsub, msgChan)

	s.log.Infof("Webhook subscriber started with %d workers, subscribed to patterns: %v", workerCount, patterns)
	return nil
}

// Stop stops the subscriber
func (s *Subscriber) Stop() error {
	if s.stopCh != nil {
		close(s.stopCh)
	}
	s.wg.Wait()
	s.log.Info("Webhook subscriber stopped")
	return nil
}

// receiver receives messages from Redis pub/sub and distributes to workers
func (s *Subscriber) receiver(ctx context.Context, pubsub *redis.PubSub, msgChan chan<- *redis.Message) {
	defer s.wg.Done()
	defer pubsub.Close()
	defer close(msgChan)

	ch := pubsub.Channel()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			select {
			case msgChan <- msg:
			case <-s.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

// worker processes messages and delivers webhooks
func (s *Subscriber) worker(ctx context.Context, workerNum int, msgChan <-chan *redis.Message) {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case msg, ok := <-msgChan:
			if !ok {
				return
			}
			s.processMessage(ctx, msg)
		}
	}
}

// processMessage processes a single Redis message and delivers to webhook endpoints
func (s *Subscriber) processMessage(ctx context.Context, msg *redis.Message) {
	// Parse the original LCM event
	var lcmEvent event.LCMEvent
	if err := json.Unmarshal([]byte(msg.Payload), &lcmEvent); err != nil {
		s.log.Errorf("Failed to unmarshal LCM event from topic %s: %v", msg.Channel, err)
		return
	}

	// Map the Redis topic to webhook event type
	eventType, ok := TopicToEventType[msg.Channel]
	if !ok {
		// Try without the prefix (the topic already has full path like "lcm.certificate.issued")
		eventType, ok = TopicToEventType[msg.Channel]
		if !ok {
			s.log.Debugf("Ignoring unrecognized topic: %s", msg.Channel)
			return
		}
	}

	// Create webhook event
	webhookEvent := &WebhookEvent{
		ID:        "evt_" + uuid.New().String()[:12],
		Type:      eventType,
		Source:    EventSource,
		Timestamp: time.Now().UTC(),
		Data:      lcmEvent.Data,
	}

	// Deliver to all matching endpoints
	endpoints := s.config.GetEndpoints()
	for _, endpoint := range endpoints {
		if !endpoint.GetEnabled() {
			continue
		}

		// Check if endpoint subscribes to this event type
		if !s.endpointWantsEvent(endpoint, eventType) {
			continue
		}

		// Deliver webhook (this includes retry logic)
		result := s.client.Deliver(ctx, endpoint, webhookEvent)
		if !result.Success {
			s.log.Warnf("Webhook delivery failed to %s: %v (attempts: %d)",
				result.URL, result.Error, result.Attempts)
		}
	}
}

// endpointWantsEvent checks if an endpoint is subscribed to a given event type
func (s *Subscriber) endpointWantsEvent(endpoint *conf.WebhookEndpoint, eventType string) bool {
	eventTypes := endpoint.GetEventTypes()
	// Empty list means all events
	if len(eventTypes) == 0 {
		return true
	}
	for _, t := range eventTypes {
		if t == eventType {
			return true
		}
	}
	return false
}

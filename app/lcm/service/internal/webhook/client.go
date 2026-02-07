package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-kratos/kratos/v2/log"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
)

// Client handles HTTP webhook delivery with retry logic
type Client struct {
	httpClient *http.Client
	config     *conf.WebhookConfig
	log        *log.Helper
}

// NewClient creates a new webhook client
func NewClient(config *conf.WebhookConfig, logger *log.Helper) *Client {
	timeout := 30 * time.Second
	if config != nil && config.GetTimeoutSeconds() > 0 {
		timeout = time.Duration(config.GetTimeoutSeconds()) * time.Second
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		config: config,
		log:    logger,
	}
}

// Deliver sends a webhook event to an endpoint with retry logic
func (c *Client) Deliver(ctx context.Context, endpoint *conf.WebhookEndpoint, event *WebhookEvent) *DeliveryResult {
	result := &DeliveryResult{
		EndpointName: endpoint.GetName(),
		URL:          endpoint.GetUrl(),
	}

	payload, err := json.Marshal(event)
	if err != nil {
		result.Error = fmt.Errorf("failed to marshal event: %w", err)
		return result
	}

	retryConfig := c.getRetryConfig()
	maxAttempts := int(retryConfig.GetMaxAttempts())
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	delay := time.Duration(retryConfig.GetInitialDelayMs()) * time.Millisecond
	if delay <= 0 {
		delay = time.Second
	}

	maxDelay := time.Duration(retryConfig.GetMaxDelayMs()) * time.Millisecond
	if maxDelay <= 0 {
		maxDelay = 60 * time.Second
	}

	backoffMultiplier := retryConfig.GetBackoffMultiplier()
	if backoffMultiplier <= 0 {
		backoffMultiplier = 2.0
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result.Attempts = attempt

		start := time.Now()
		statusCode, err := c.send(ctx, endpoint, event, payload)
		result.Duration = time.Since(start)
		result.StatusCode = statusCode

		if err == nil && statusCode >= 200 && statusCode < 300 {
			result.Success = true
			c.log.Debugf("Webhook delivered successfully to %s (attempt %d, status %d)",
				endpoint.GetUrl(), attempt, statusCode)
			return result
		}

		if err != nil {
			result.Error = err
		} else {
			result.Error = fmt.Errorf("received non-2xx status code: %d", statusCode)
		}

		// Don't retry on client errors (4xx) except 408 (Request Timeout) and 429 (Too Many Requests)
		if statusCode >= 400 && statusCode < 500 && statusCode != 408 && statusCode != 429 {
			c.log.Warnf("Webhook delivery to %s failed with client error (status %d), not retrying",
				endpoint.GetUrl(), statusCode)
			return result
		}

		if attempt < maxAttempts {
			c.log.Warnf("Webhook delivery to %s failed (attempt %d/%d, status %d): %v, retrying in %s",
				endpoint.GetUrl(), attempt, maxAttempts, statusCode, err, delay)

			select {
			case <-ctx.Done():
				result.Error = ctx.Err()
				return result
			case <-time.After(delay):
			}

			// Calculate next delay with exponential backoff
			delay = time.Duration(float64(delay) * float64(backoffMultiplier))
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}

	c.log.Errorf("Webhook delivery to %s failed after %d attempts: %v",
		endpoint.GetUrl(), maxAttempts, result.Error)
	return result
}

// send performs a single HTTP request to the webhook endpoint
func (c *Client) send(ctx context.Context, endpoint *conf.WebhookEndpoint, event *WebhookEvent, payload []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.GetUrl(), bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set standard headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-ID", event.ID)
	req.Header.Set("X-Webhook-Event", event.Type)

	// Add HMAC signature if secret is configured
	if secret := endpoint.GetSecret(); secret != "" {
		signature := c.computeSignature(payload, secret)
		req.Header.Set("X-Webhook-Signature", "sha256="+signature)
	}

	// Add custom headers
	for key, value := range endpoint.GetHeaders() {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read and discard body to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

// computeSignature computes HMAC-SHA256 signature for the payload
func (c *Client) computeSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// getRetryConfig returns the retry configuration with defaults
func (c *Client) getRetryConfig() *conf.WebhookRetryConfig {
	if c.config != nil && c.config.GetRetry() != nil {
		return c.config.GetRetry()
	}
	return &conf.WebhookRetryConfig{}
}

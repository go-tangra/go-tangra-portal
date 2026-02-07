package biz

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
)

// PropagationResult contains the result of a DNS propagation check
type PropagationResult struct {
	Success       bool
	Attempts      int
	Duration      time.Duration
	FoundValues   []string
	ServerResults map[string]bool // server -> success
}

// DNSPropagationChecker handles DNS propagation verification with exponential backoff
type DNSPropagationChecker struct {
	logger     *log.Helper
	dnsServers []string      // Multiple public DNS servers
	maxRetries int           // Maximum number of retry attempts
	baseDelay  time.Duration // Base delay between retries
	maxDelay   time.Duration // Maximum delay between retries
	timeout    time.Duration // Timeout for each DNS query
	threshold  float64       // Percentage of servers that must confirm (0.0-1.0)
}

// DNSPropagationCheckerOption configures the propagation checker
type DNSPropagationCheckerOption func(*DNSPropagationChecker)

// WithDNSServers sets custom DNS servers
func WithDNSServers(servers []string) DNSPropagationCheckerOption {
	return func(c *DNSPropagationChecker) {
		c.dnsServers = servers
	}
}

// WithMaxRetries sets maximum retry attempts
func WithMaxRetries(max int) DNSPropagationCheckerOption {
	return func(c *DNSPropagationChecker) {
		c.maxRetries = max
	}
}

// WithBaseDelay sets base delay between retries
func WithBaseDelay(delay time.Duration) DNSPropagationCheckerOption {
	return func(c *DNSPropagationChecker) {
		c.baseDelay = delay
	}
}

// WithMaxDelay sets maximum delay between retries
func WithMaxDelay(delay time.Duration) DNSPropagationCheckerOption {
	return func(c *DNSPropagationChecker) {
		c.maxDelay = delay
	}
}

// WithThreshold sets the percentage of servers that must confirm propagation
func WithThreshold(threshold float64) DNSPropagationCheckerOption {
	return func(c *DNSPropagationChecker) {
		c.threshold = threshold
	}
}

// NewDNSPropagationChecker creates a new DNS propagation checker
func NewDNSPropagationChecker(logger log.Logger, opts ...DNSPropagationCheckerOption) *DNSPropagationChecker {
	checker := &DNSPropagationChecker{
		logger: log.NewHelper(log.With(logger, "module", "lcm/dns-propagation")),
		dnsServers: []string{
			"8.8.8.8:53",        // Google DNS
			"8.8.4.4:53",        // Google DNS Secondary
			"1.1.1.1:53",        // Cloudflare DNS
			"1.0.0.1:53",        // Cloudflare DNS Secondary
			"208.67.222.222:53", // OpenDNS
			"208.67.220.220:53", // OpenDNS Secondary
		},
		maxRetries: 60,               // Up to 60 attempts
		baseDelay:  2 * time.Second,  // Start with 2s delay
		maxDelay:   120 * time.Second, // Max 2 minutes between retries
		timeout:    10 * time.Second,  // 10s timeout per query
		threshold:  0.6,               // 60% of servers must confirm
	}

	for _, opt := range opts {
		opt(checker)
	}

	return checker
}

// WaitForPropagation waits for DNS TXT record propagation with exponential backoff
func (c *DNSPropagationChecker) WaitForPropagation(ctx context.Context, domain, recordName, expectedValue string) (*PropagationResult, error) {
	startTime := time.Now()
	result := &PropagationResult{
		ServerResults: make(map[string]bool),
	}

	c.logger.Infof("Waiting for DNS propagation: record=%s, expected=%s", recordName, expectedValue)

	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(startTime)
			result.Attempts = attempt
			return result, ctx.Err()
		default:
		}

		// Check propagation across all DNS servers
		propagated, foundValues, serverResults := c.checkAllServers(ctx, recordName, expectedValue)
		result.FoundValues = foundValues
		result.ServerResults = serverResults

		if propagated {
			result.Success = true
			result.Attempts = attempt
			result.Duration = time.Since(startTime)
			c.logger.Infof("DNS propagation confirmed after %d attempts (%s)", attempt, result.Duration)
			return result, nil
		}

		// Calculate backoff delay
		delay := c.calculateBackoffDelay(attempt)
		c.logger.Debugf("DNS propagation attempt %d/%d failed, waiting %s before retry",
			attempt, c.maxRetries, delay)

		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			result.Duration = time.Since(startTime)
			result.Attempts = attempt
			return result, ctx.Err()
		}
	}

	result.Duration = time.Since(startTime)
	result.Attempts = c.maxRetries
	return result, fmt.Errorf("DNS propagation failed after %d attempts (%s)", c.maxRetries, result.Duration)
}

// checkAllServers checks DNS TXT record across all configured DNS servers
func (c *DNSPropagationChecker) checkAllServers(ctx context.Context, recordName, expectedValue string) (bool, []string, map[string]bool) {
	serverResults := make(map[string]bool)
	foundValues := make(map[string]bool)
	successCount := 0

	for _, server := range c.dnsServers {
		values, err := c.queryTXTRecord(ctx, server, recordName)
		if err != nil {
			c.logger.Debugf("DNS query failed for %s on %s: %v", recordName, server, err)
			serverResults[server] = false
			continue
		}

		// Check if expected value is found
		found := false
		for _, v := range values {
			foundValues[v] = true
			if v == expectedValue {
				found = true
				break
			}
		}

		serverResults[server] = found
		if found {
			successCount++
		}
	}

	// Convert found values map to slice
	var foundList []string
	for v := range foundValues {
		foundList = append(foundList, v)
	}

	// Check if threshold is met
	threshold := int(math.Ceil(float64(len(c.dnsServers)) * c.threshold))
	propagated := successCount >= threshold

	c.logger.Debugf("DNS propagation check: %d/%d servers confirmed (threshold: %d)",
		successCount, len(c.dnsServers), threshold)

	return propagated, foundList, serverResults
}

// queryTXTRecord queries TXT records from a specific DNS server
func (c *DNSPropagationChecker) queryTXTRecord(ctx context.Context, server, recordName string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: c.timeout,
			}
			return d.DialContext(ctx, "udp", server)
		},
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	records, err := resolver.LookupTXT(ctx, strings.TrimSuffix(recordName, "."))
	if err != nil {
		return nil, err
	}

	return records, nil
}

// calculateBackoffDelay calculates the delay for the given attempt using exponential backoff with jitter
func (c *DNSPropagationChecker) calculateBackoffDelay(attempt int) time.Duration {
	// Exponential backoff: delay = baseDelay * 2^(attempt-1)
	delay := time.Duration(float64(c.baseDelay) * math.Pow(2, float64(attempt-1)))

	// Cap at max delay
	if delay > c.maxDelay {
		delay = c.maxDelay
	}

	// Add jitter (±10%)
	jitter := time.Duration(float64(delay) * 0.1 * (2*rand.Float64() - 1))
	delay += jitter

	return delay
}

// CheckOnce performs a single DNS propagation check without retrying
func (c *DNSPropagationChecker) CheckOnce(ctx context.Context, recordName, expectedValue string) (bool, map[string]bool) {
	propagated, _, serverResults := c.checkAllServers(ctx, recordName, expectedValue)
	return propagated, serverResults
}

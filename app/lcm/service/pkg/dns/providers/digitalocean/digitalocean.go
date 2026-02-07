package digitalocean

import (
	"errors"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/digitalocean"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// ChallengeProviderConfig configuration for DigitalOcean DNS challenge provider
type ChallengeProviderConfig struct {
	// AuthToken is the DigitalOcean API token
	AuthToken string `json:"authToken"`
	
	// BaseURL is the DigitalOcean API base URL (optional, defaults to official API)
	BaseURL string `json:"baseUrl,omitempty"`
	
	// DnsPropagationTimeout is the DNS propagation timeout in seconds
	DnsPropagationTimeout int32 `json:"dnsPropagationTimeout,omitempty"`
	
	// DnsPollingInterval is the DNS polling interval in seconds
	DnsPollingInterval int32 `json:"dnsPollingInterval,omitempty"`
	
	// DnsTTL is the TTL for DNS records in seconds
	DnsTTL int32 `json:"dnsTTL,omitempty"`
}

// NewChallengeProvider creates a new DigitalOcean DNS challenge provider
func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	if config.AuthToken == "" {
		return nil, errors.New("digitalOcean auth token is required")
	}

	// Configure the provider
	providerConfig := digitalocean.NewDefaultConfig()
	providerConfig.AuthToken = config.AuthToken
	
	if config.BaseURL != "" {
		providerConfig.BaseURL = config.BaseURL
	}
	
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	
	if config.DnsPollingInterval != 0 {
		providerConfig.PollingInterval = time.Duration(config.DnsPollingInterval) * time.Second
	}
	
	if config.DnsTTL != 0 {
		providerConfig.TTL = int(config.DnsTTL)
	}

	provider, err := digitalocean.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	return provider, nil
}
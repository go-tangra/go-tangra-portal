package hurricane

import (
	"errors"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/hurricane"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// ChallengeProviderConfig configuration for Hurricane Electric DNS challenge provider
type ChallengeProviderConfig struct {
	// Credentials is a map of domain names to their corresponding tokens
	// Format: {"example.com": "token1", "subdomain.example.com": "token2"}
	Credentials map[string]string `json:"credentials"`
	
	// DnsPropagationTimeout is the DNS propagation timeout in seconds
	DnsPropagationTimeout int32 `json:"dnsPropagationTimeout,omitempty"`
	
	// DnsPollingInterval is the DNS polling interval in seconds
	DnsPollingInterval int32 `json:"dnsPollingInterval,omitempty"`
	
	// DnsSequenceInterval is the DNS sequence interval in seconds
	DnsSequenceInterval int32 `json:"dnsSequenceInterval,omitempty"`
}

// NewChallengeProvider creates a new Hurricane Electric DNS challenge provider
func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	if len(config.Credentials) == 0 {
		return nil, errors.New("hurricane Electric credentials are required (at least one domain-token pair)")
	}

	// Validate that all credentials have non-empty values
	for domain, token := range config.Credentials {
		if domain == "" {
			return nil, errors.New("hurricane Electric credential domain cannot be empty")
		}
		if token == "" {
			return nil, errors.New("hurricane Electric credential token cannot be empty")
		}
	}

	// Configure the provider
	providerConfig := hurricane.NewDefaultConfig()
	providerConfig.Credentials = config.Credentials
	
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	
	if config.DnsPollingInterval != 0 {
		providerConfig.PollingInterval = time.Duration(config.DnsPollingInterval) * time.Second
	}
	
	if config.DnsSequenceInterval != 0 {
		providerConfig.SequenceInterval = time.Duration(config.DnsSequenceInterval) * time.Second
	}

	provider, err := hurricane.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	return provider, nil
}
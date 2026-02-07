package easydns

import (
	"errors"
	"net/url"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/easydns"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// ChallengeProviderConfig configuration for EasyDNS challenge provider
type ChallengeProviderConfig struct {
	// Token is the EasyDNS API token
	Token string `json:"token"`
	
	// Key is the EasyDNS API key
	Key string `json:"key"`
	
	// Endpoint is the EasyDNS API endpoint (optional, defaults to production API)
	Endpoint string `json:"endpoint,omitempty"`
	
	// DnsPropagationTimeout is the DNS propagation timeout in seconds
	DnsPropagationTimeout int32 `json:"dnsPropagationTimeout,omitempty"`
	
	// DnsPollingInterval is the DNS polling interval in seconds
	DnsPollingInterval int32 `json:"dnsPollingInterval,omitempty"`
	
	// DnsSequenceInterval is the DNS sequence interval in seconds
	DnsSequenceInterval int32 `json:"dnsSequenceInterval,omitempty"`
	
	// DnsTTL is the TTL for DNS records in seconds
	DnsTTL int32 `json:"dnsTTL,omitempty"`
}

// NewChallengeProvider creates a new EasyDNS challenge provider
func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	if config.Token == "" {
		return nil, errors.New("easyDNS token is required")
	}

	if config.Key == "" {
		return nil, errors.New("easyDNS key is required")
	}

	// Configure the provider
	providerConfig := easydns.NewDefaultConfig()
	providerConfig.Token = config.Token
	providerConfig.Key = config.Key
	
	if config.Endpoint != "" {
		endpointURL, err := url.Parse(config.Endpoint)
		if err != nil {
			return nil, errors.New("invalid easyDNS endpoint URL")
		}
		providerConfig.Endpoint = endpointURL
	}
	
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	
	if config.DnsPollingInterval != 0 {
		providerConfig.PollingInterval = time.Duration(config.DnsPollingInterval) * time.Second
	}
	
	if config.DnsSequenceInterval != 0 {
		providerConfig.SequenceInterval = time.Duration(config.DnsSequenceInterval) * time.Second
	}
	
	if config.DnsTTL != 0 {
		providerConfig.TTL = int(config.DnsTTL)
	}

	provider, err := easydns.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	return provider, nil
}
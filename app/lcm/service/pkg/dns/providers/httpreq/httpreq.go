package httpreq

import (
	"errors"
	"net/url"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/httpreq"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// ChallengeProviderConfig configuration for HTTP Request DNS challenge provider
type ChallengeProviderConfig struct {
	// Endpoint is the HTTP endpoint URL that will handle DNS record operations
	Endpoint string `json:"endpoint"`
	
	// Mode defines the operation mode ("RAW" or other provider-specific modes)
	Mode string `json:"mode,omitempty"`
	
	// Username for HTTP basic authentication (optional)
	Username string `json:"username,omitempty"`
	
	// Password for HTTP basic authentication (optional)
	Password string `json:"password,omitempty"`
	
	// DnsPropagationTimeout is the DNS propagation timeout in seconds
	DnsPropagationTimeout int32 `json:"dnsPropagationTimeout,omitempty"`
	
	// DnsPollingInterval is the DNS polling interval in seconds
	DnsPollingInterval int32 `json:"dnsPollingInterval,omitempty"`
}

// NewChallengeProvider creates a new HTTP Request DNS challenge provider
func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	if config.Endpoint == "" {
		return nil, errors.New("HTTP request endpoint is required")
	}

	// Parse and validate endpoint URL
	endpointURL, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, errors.New("invalid HTTP request endpoint URL")
	}

	// Configure the provider
	providerConfig := httpreq.NewDefaultConfig()
	providerConfig.Endpoint = endpointURL
	
	if config.Mode != "" {
		providerConfig.Mode = config.Mode
	}
	
	if config.Username != "" {
		providerConfig.Username = config.Username
	}
	
	if config.Password != "" {
		providerConfig.Password = config.Password
	}
	
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	
	if config.DnsPollingInterval != 0 {
		providerConfig.PollingInterval = time.Duration(config.DnsPollingInterval) * time.Second
	}

	provider, err := httpreq.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	return provider, nil
}
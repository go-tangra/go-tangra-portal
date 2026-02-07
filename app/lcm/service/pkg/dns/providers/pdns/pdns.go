package pdns

import (
	"errors"
	"net/url"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/pdns"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// ChallengeProviderConfig configuration for PowerDNS challenge provider
type ChallengeProviderConfig struct {
	// APIKey is the PowerDNS API key
	APIKey string `json:"apiKey"`
	
	// Host is the PowerDNS server URL
	Host string `json:"host"`
	
	// ServerName is the PowerDNS server name (zone server)
	ServerName string `json:"serverName,omitempty"`
	
	// APIVersion is the PowerDNS API version (default: 1)
	APIVersion int32 `json:"apiVersion,omitempty"`
	
	// DnsPropagationTimeout is the DNS propagation timeout in seconds
	DnsPropagationTimeout int32 `json:"dnsPropagationTimeout,omitempty"`
	
	// DnsPollingInterval is the DNS polling interval in seconds
	DnsPollingInterval int32 `json:"dnsPollingInterval,omitempty"`
	
	// DnsTTL is the TTL for DNS records in seconds
	DnsTTL int32 `json:"dnsTTL,omitempty"`
}

// NewChallengeProvider creates a new PowerDNS challenge provider
func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	if config.APIKey == "" {
		return nil, errors.New("powerDNS API key is required")
	}

	if config.Host == "" {
		return nil, errors.New("powerDNS host is required")
	}

	// Parse and validate host URL
	hostURL, err := url.Parse(config.Host)
	if err != nil {
		return nil, errors.New("invalid powerDNS host URL")
	}

	// Configure the provider
	providerConfig := pdns.NewDefaultConfig()
	providerConfig.APIKey = config.APIKey
	providerConfig.Host = hostURL
	
	if config.ServerName != "" {
		providerConfig.ServerName = config.ServerName
	}
	
	if config.APIVersion != 0 {
		providerConfig.APIVersion = int(config.APIVersion)
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

	provider, err := pdns.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	return provider, nil
}
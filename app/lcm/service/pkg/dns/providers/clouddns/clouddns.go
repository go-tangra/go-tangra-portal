package clouddns

import (
	"errors"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/clouddns"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// ChallengeProviderConfig configuration for CloudDNS challenge provider
type ChallengeProviderConfig struct {
	// ClientID is the CloudDNS client ID
	ClientID string `json:"clientId"`
	
	// Email is the CloudDNS account email
	Email string `json:"email"`
	
	// Password is the CloudDNS account password
	Password string `json:"password"`
	
	// DnsPropagationTimeout is the DNS propagation timeout in seconds
	DnsPropagationTimeout int32 `json:"dnsPropagationTimeout,omitempty"`
	
	// DnsPollingInterval is the DNS polling interval in seconds
	DnsPollingInterval int32 `json:"dnsPollingInterval,omitempty"`
	
	// DnsTTL is the TTL for DNS records in seconds
	DnsTTL int32 `json:"dnsTTL,omitempty"`
}

// NewChallengeProvider creates a new CloudDNS challenge provider
func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	if config.ClientID == "" {
		return nil, errors.New("cloudDNS client ID is required")
	}

	if config.Email == "" {
		return nil, errors.New("cloudDNS email is required")
	}

	if config.Password == "" {
		return nil, errors.New("cloudDNS password is required")
	}

	// Configure the provider
	providerConfig := clouddns.NewDefaultConfig()
	providerConfig.ClientID = config.ClientID
	providerConfig.Email = config.Email
	providerConfig.Password = config.Password
	
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	
	if config.DnsPollingInterval != 0 {
		providerConfig.PollingInterval = time.Duration(config.DnsPollingInterval) * time.Second
	}
	
	if config.DnsTTL != 0 {
		providerConfig.TTL = int(config.DnsTTL)
	}

	provider, err := clouddns.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	return provider, nil
}
package gcloud

import (
	"errors"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/gcloud"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// ChallengeProviderConfig configuration for Google Cloud DNS ACME challenge provider
type ChallengeProviderConfig struct {
	// Project is the Google Cloud Project ID
	Project string `json:"project"`
	
	// ZoneID is the DNS zone ID (optional, will be auto-detected if not provided)
	ZoneID string `json:"zoneId,omitempty"`
	
	// ServiceAccountFile is the path to the service account JSON file
	ServiceAccountFile string `json:"serviceAccountFile,omitempty"`
	
	// ServiceAccountKey is the service account JSON key content (as alternative to file)
	ServiceAccountKey string `json:"serviceAccountKey,omitempty"`
	
	// AllowPrivateZone allows using private DNS zones
	AllowPrivateZone bool `json:"allowPrivateZone,omitempty"`
	
	// ImpersonateServiceAccount is the service account email to impersonate
	ImpersonateServiceAccount string `json:"impersonateServiceAccount,omitempty"`
	
	// DnsPropagationTimeout is the DNS propagation timeout in seconds
	DnsPropagationTimeout int32 `json:"dnsPropagationTimeout,omitempty"`
	
	// DnsPollingInterval is the DNS polling interval in seconds
	DnsPollingInterval int32 `json:"dnsPollingInterval,omitempty"`
	
	// DnsTTL is the TTL for DNS records in seconds
	DnsTTL int32 `json:"dnsTTL,omitempty"`
	
	// Debug enables debug logging
	Debug bool `json:"debug,omitempty"`
}

// NewChallengeProvider creates a new Google Cloud DNS challenge provider
func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	if config.Project == "" {
		return nil, errors.New("google cloud project is required")
	}

	// Configure the provider with additional options
	providerConfig := gcloud.NewDefaultConfig()
	providerConfig.Project = config.Project
	providerConfig.Debug = config.Debug
	
	if config.ZoneID != "" {
		providerConfig.ZoneID = config.ZoneID
	}
	
	if config.AllowPrivateZone {
		providerConfig.AllowPrivateZone = config.AllowPrivateZone
	}
	
	if config.ImpersonateServiceAccount != "" {
		providerConfig.ImpersonateServiceAccount = config.ImpersonateServiceAccount
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

	// Create a new provider based on available authentication method
	var provider *gcloud.DNSProvider
	var err error

	if config.ServiceAccountKey != "" {
		// Use service account key content
		provider, err = gcloud.NewDNSProviderServiceAccountKey([]byte(config.ServiceAccountKey))
		if err != nil {
			return nil, err
		}
	} else if config.ServiceAccountFile != "" {
		// Use service account file
		provider, err = gcloud.NewDNSProviderServiceAccount(config.ServiceAccountFile)
		if err != nil {
			return nil, err
		}
	} else {
		// Use configuration with credentials from environment or default application credentials
		provider, err = gcloud.NewDNSProviderConfig(providerConfig)
		if err != nil {
			return nil, err
		}
	}

	return provider, nil
}
package acmedns

import (
	"errors"

	"github.com/go-acme/lego/v4/providers/dns/acmedns"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
)

// ChallengeProviderConfig configuration for ACME-DNS challenge provider
type ChallengeProviderConfig struct {
	// APIBase is the ACME-DNS server base URL
	APIBase string `json:"apiBase,omitempty"`

	// AllowList restricts the domains that can be updated
	AllowList []string `json:"allowList,omitempty"`

	// StoragePath is the path to store ACME-DNS account information
	StoragePath string `json:"storagePath,omitempty"`

	// StorageBaseURL is the base URL for storage backend (e.g., for remote storage)
	StorageBaseURL string `json:"storageBaseUrl,omitempty"`
}

// NewChallengeProvider creates a new ACME-DNS challenge provider
func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	// Configure the provider
	providerConfig := acmedns.NewDefaultConfig()

	if config.APIBase != "" {
		providerConfig.APIBase = config.APIBase
	}

	if len(config.AllowList) > 0 {
		providerConfig.AllowList = config.AllowList
	}

	if config.StoragePath != "" {
		providerConfig.StoragePath = config.StoragePath
	}

	if config.StorageBaseURL != "" {
		providerConfig.StorageBaseURL = config.StorageBaseURL
	}

	provider, err := acmedns.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

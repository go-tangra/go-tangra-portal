package dns

import (
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/registry"
)

// Wrapper functions that delegate to the registry package

// GetProvider creates a DNS provider instance by name and configuration
func GetProvider(name string, config map[string]string) (ACMEChallenger, error) {
	provider, err := registry.GetProvider(name, config)
	if err != nil {
		return nil, err
	}
	return provider.(ACMEChallenger), nil
}

// ListProviders returns a list of all registered providers
func ListProviders() []string {
	return registry.ListProviders()
}

// GetProviderInfo returns information about a registered provider
func GetProviderInfo(name string) (*registry.ProviderInfo, error) {
	return registry.GetProviderInfo(name)
}

// GetAllProviderInfo returns information about all registered providers
func GetAllProviderInfo() map[string]*registry.ProviderInfo {
	return registry.GetAllProviderInfo()
}

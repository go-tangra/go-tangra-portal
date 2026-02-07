package init

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/registry"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/acmedns"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/cloudflare"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/clouddns"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/digitalocean"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/easydns"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/gcloud"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/hurricane"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/httpreq"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/pdns"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/providers/route53"
)

func init() {
	// Register all available DNS providers
	registerAllProviders()
}

// registerAllProviders registers all available DNS providers
func registerAllProviders() {
	// Register ACME-DNS provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "acmedns",
		Description: "ACME-DNS external DNS server for DNS-01 challenges",
		RequiredFields: []string{},
		OptionalFields: []string{"apiBase", "allowList", "storagePath", "storageBaseUrl"},
		Factory:     createACMEDNSProvider,
	})

	// Register Cloudflare provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "cloudflare",
		Description: "Cloudflare DNS API",
		RequiredFields: []string{"dnsApiToken"},
		OptionalFields: []string{"zoneApiToken", "dnsPropagationTimeout", "dnsTTL"},
		Factory:     createCloudflareProvider,
	})

	// Register CloudDNS provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "clouddns",
		Description: "CloudDNS API",
		RequiredFields: []string{"clientId", "email", "password"},
		OptionalFields: []string{"dnsPropagationTimeout", "dnsPollingInterval", "dnsTTL"},
		Factory:     createCloudDNSProvider,
	})

	// Register DigitalOcean provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "digitalocean",
		Description: "DigitalOcean DNS API",
		RequiredFields: []string{"authToken"},
		OptionalFields: []string{"baseUrl", "dnsPropagationTimeout", "dnsPollingInterval", "dnsTTL"},
		Factory:     createDigitalOceanProvider,
	})

	// Register EasyDNS provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "easydns",
		Description: "EasyDNS API",
		RequiredFields: []string{"token", "key"},
		OptionalFields: []string{"endpoint", "dnsPropagationTimeout", "dnsPollingInterval", "dnsSequenceInterval", "dnsTTL"},
		Factory:     createEasyDNSProvider,
	})

	// Register Google Cloud DNS provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "gcloud",
		Description: "Google Cloud DNS API",
		RequiredFields: []string{"project"},
		OptionalFields: []string{"serviceAccountKey", "serviceAccountFile", "zoneId", "allowPrivateZone", "impersonateServiceAccount", "dnsPropagationTimeout", "dnsPollingInterval", "dnsTTL", "debug"},
		Factory:     createGCloudProvider,
	})

	// Register Hurricane Electric provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "hurricane",
		Description: "Hurricane Electric Free DNS",
		RequiredFields: []string{"credentials"},
		OptionalFields: []string{"dnsPropagationTimeout", "dnsPollingInterval", "dnsSequenceInterval"},
		Factory:     createHurricaneProvider,
	})

	// Register HTTP Request provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "httpreq",
		Description: "Generic HTTP endpoint for DNS operations",
		RequiredFields: []string{"endpoint"},
		OptionalFields: []string{"mode", "username", "password", "dnsPropagationTimeout", "dnsPollingInterval"},
		Factory:     createHTTPReqProvider,
	})

	// Register PowerDNS provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "pdns",
		Description: "PowerDNS Authoritative Server API",
		RequiredFields: []string{"apiKey", "host"},
		OptionalFields: []string{"serverName", "apiVersion", "dnsPropagationTimeout", "dnsPollingInterval", "dnsTTL"},
		Factory:     createPowerDNSProvider,
	})

	// Register Route53 provider
	registry.RegisterProvider(&registry.ProviderInfo{
		Name:        "route53",
		Description: "Amazon Route53 DNS API",
		RequiredFields: []string{"accessKeyId", "secretAccessKey", "region"},
		OptionalFields: []string{"hostedZoneId", "dnsPropagationTimeout", "dnsTTL"},
		Factory:     createRoute53Provider,
	})
}

// Provider factory functions

func createACMEDNSProvider(config map[string]string) (challenge.Provider, error) {
	providerConfig := &acmedns.ChallengeProviderConfig{
		APIBase:        registry.GetString(config, "apiBase", ""),
		AllowList:      registry.GetStringSlice(config, "allowList"),
		StoragePath:    registry.GetString(config, "storagePath", ""),
		StorageBaseURL: registry.GetString(config, "storageBaseUrl", ""),
	}

	return acmedns.NewChallengeProvider(providerConfig)
}

func createCloudflareProvider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	ttl, err := registry.GetInt32(config, "dnsTTL", 0)
	if err != nil {
		return nil, err
	}

	providerConfig := &cloudflare.ChallengeProviderConfig{
		DnsApiToken:           registry.GetString(config, "dnsApiToken", ""),
		ZoneApiToken:          registry.GetString(config, "zoneApiToken", ""),
		DnsPropagationTimeout: timeout,
		DnsTTL:                ttl,
	}

	return cloudflare.NewChallengeProvider(providerConfig)
}

func createCloudDNSProvider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	polling, err := registry.GetInt32(config, "dnsPollingInterval", 0)
	if err != nil {
		return nil, err
	}

	ttl, err := registry.GetInt32(config, "dnsTTL", 0)
	if err != nil {
		return nil, err
	}

	providerConfig := &clouddns.ChallengeProviderConfig{
		ClientID:              registry.GetString(config, "clientId", ""),
		Email:                 registry.GetString(config, "email", ""),
		Password:              registry.GetString(config, "password", ""),
		DnsPropagationTimeout: timeout,
		DnsPollingInterval:    polling,
		DnsTTL:                ttl,
	}

	return clouddns.NewChallengeProvider(providerConfig)
}

func createDigitalOceanProvider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	polling, err := registry.GetInt32(config, "dnsPollingInterval", 0)
	if err != nil {
		return nil, err
	}

	ttl, err := registry.GetInt32(config, "dnsTTL", 0)
	if err != nil {
		return nil, err
	}

	providerConfig := &digitalocean.ChallengeProviderConfig{
		AuthToken:             registry.GetString(config, "authToken", ""),
		BaseURL:               registry.GetString(config, "baseUrl", ""),
		DnsPropagationTimeout: timeout,
		DnsPollingInterval:    polling,
		DnsTTL:                ttl,
	}

	return digitalocean.NewChallengeProvider(providerConfig)
}

func createEasyDNSProvider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	polling, err := registry.GetInt32(config, "dnsPollingInterval", 0)
	if err != nil {
		return nil, err
	}

	sequence, err := registry.GetInt32(config, "dnsSequenceInterval", 0)
	if err != nil {
		return nil, err
	}

	ttl, err := registry.GetInt32(config, "dnsTTL", 0)
	if err != nil {
		return nil, err
	}

	providerConfig := &easydns.ChallengeProviderConfig{
		Token:                 registry.GetString(config, "token", ""),
		Key:                   registry.GetString(config, "key", ""),
		Endpoint:              registry.GetString(config, "endpoint", ""),
		DnsPropagationTimeout: timeout,
		DnsPollingInterval:    polling,
		DnsSequenceInterval:   sequence,
		DnsTTL:                ttl,
	}

	return easydns.NewChallengeProvider(providerConfig)
}

func createGCloudProvider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	polling, err := registry.GetInt32(config, "dnsPollingInterval", 0)
	if err != nil {
		return nil, err
	}

	ttl, err := registry.GetInt32(config, "dnsTTL", 0)
	if err != nil {
		return nil, err
	}

	allowPrivate, err := registry.GetBool(config, "allowPrivateZone", false)
	if err != nil {
		return nil, err
	}

	debug, err := registry.GetBool(config, "debug", false)
	if err != nil {
		return nil, err
	}

	providerConfig := &gcloud.ChallengeProviderConfig{
		Project:                   registry.GetString(config, "project", ""),
		ZoneID:                    registry.GetString(config, "zoneId", ""),
		ServiceAccountFile:        registry.GetString(config, "serviceAccountFile", ""),
		ServiceAccountKey:         registry.GetString(config, "serviceAccountKey", ""),
		AllowPrivateZone:          allowPrivate,
		ImpersonateServiceAccount: registry.GetString(config, "impersonateServiceAccount", ""),
		DnsPropagationTimeout:     timeout,
		DnsPollingInterval:        polling,
		DnsTTL:                    ttl,
		Debug:                     debug,
	}

	return gcloud.NewChallengeProvider(providerConfig)
}

func createHurricaneProvider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	polling, err := registry.GetInt32(config, "dnsPollingInterval", 0)
	if err != nil {
		return nil, err
	}

	sequence, err := registry.GetInt32(config, "dnsSequenceInterval", 0)
	if err != nil {
		return nil, err
	}

	credentials, err := registry.GetJSONMap(config, "credentials")
	if err != nil {
		return nil, err
	}

	providerConfig := &hurricane.ChallengeProviderConfig{
		Credentials:           credentials,
		DnsPropagationTimeout: timeout,
		DnsPollingInterval:    polling,
		DnsSequenceInterval:   sequence,
	}

	return hurricane.NewChallengeProvider(providerConfig)
}

func createHTTPReqProvider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	polling, err := registry.GetInt32(config, "dnsPollingInterval", 0)
	if err != nil {
		return nil, err
	}

	providerConfig := &httpreq.ChallengeProviderConfig{
		Endpoint:              registry.GetString(config, "endpoint", ""),
		Mode:                  registry.GetString(config, "mode", ""),
		Username:              registry.GetString(config, "username", ""),
		Password:              registry.GetString(config, "password", ""),
		DnsPropagationTimeout: timeout,
		DnsPollingInterval:    polling,
	}

	return httpreq.NewChallengeProvider(providerConfig)
}

func createPowerDNSProvider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	polling, err := registry.GetInt32(config, "dnsPollingInterval", 0)
	if err != nil {
		return nil, err
	}

	ttl, err := registry.GetInt32(config, "dnsTTL", 0)
	if err != nil {
		return nil, err
	}

	apiVersion, err := registry.GetInt32(config, "apiVersion", 0)
	if err != nil {
		return nil, err
	}

	providerConfig := &pdns.ChallengeProviderConfig{
		APIKey:                registry.GetString(config, "apiKey", ""),
		Host:                  registry.GetString(config, "host", ""),
		ServerName:            registry.GetString(config, "serverName", ""),
		APIVersion:            apiVersion,
		DnsPropagationTimeout: timeout,
		DnsPollingInterval:    polling,
		DnsTTL:                ttl,
	}

	return pdns.NewChallengeProvider(providerConfig)
}

func createRoute53Provider(config map[string]string) (challenge.Provider, error) {
	timeout, err := registry.GetInt32(config, "dnsPropagationTimeout", 0)
	if err != nil {
		return nil, err
	}

	ttl, err := registry.GetInt32(config, "dnsTTL", 0)
	if err != nil {
		return nil, err
	}

	providerConfig := &route53.ChallengeProviderConfig{
		AccessKeyId:           registry.GetString(config, "accessKeyId", ""),
		SecretAccessKey:       registry.GetString(config, "secretAccessKey", ""),
		Region:                registry.GetString(config, "region", ""),
		HostedZoneId:          registry.GetString(config, "hostedZoneId", ""),
		DnsPropagationTimeout: timeout,
		DnsTTL:                ttl,
	}

	return route53.NewChallengeProvider(providerConfig)
}
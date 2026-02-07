package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// TestConfig holds the configuration for functional tests
type TestConfig struct {
	Server      ServerConfig      `yaml:"server"`
	ACME        ACMEConfig        `yaml:"acme"`
	DNSProvider DNSProviderConfig `yaml:"dns_provider"`
	TestDomain  TestDomainConfig  `yaml:"test_domain"`
	Timeouts    TimeoutConfig     `yaml:"timeouts"`
}

// ServerConfig holds LCM server configuration
type ServerConfig struct {
	Address      string `yaml:"address"`
	CAFile       string `yaml:"ca_file"`
	SharedSecret string `yaml:"shared_secret"`
}

// ACMEConfig holds ACME-specific configuration
type ACMEConfig struct {
	Endpoint string `yaml:"endpoint"`
	Email    string `yaml:"email"`
	// Optional EAB credentials for providers like ZeroSSL
	EabKid     string `yaml:"eab_kid,omitempty"`
	EabHmacKey string `yaml:"eab_hmac_key,omitempty"`
}

// DNSProviderConfig holds DNS provider configuration
type DNSProviderConfig struct {
	Name   string            `yaml:"name"`
	Config map[string]string `yaml:"config"`
}

// TestDomainConfig holds test domain configuration
type TestDomainConfig struct {
	Domain   string   `yaml:"domain"`
	DNSNames []string `yaml:"dns_names"`
}

// TimeoutConfig holds timeout configuration
type TimeoutConfig struct {
	DNSPropagation      int `yaml:"dns_propagation"`
	CertificateIssuance int `yaml:"certificate_issuance"`
	PollInterval        int `yaml:"poll_interval"`
}

// GetDNSPropagationTimeout returns DNS propagation timeout as duration
func (t TimeoutConfig) GetDNSPropagationTimeout() time.Duration {
	if t.DNSPropagation <= 0 {
		return 5 * time.Minute // default
	}
	return time.Duration(t.DNSPropagation) * time.Second
}

// GetCertificateIssuanceTimeout returns certificate issuance timeout as duration
func (t TimeoutConfig) GetCertificateIssuanceTimeout() time.Duration {
	if t.CertificateIssuance <= 0 {
		return 10 * time.Minute // default
	}
	return time.Duration(t.CertificateIssuance) * time.Second
}

// GetPollInterval returns poll interval as duration
func (t TimeoutConfig) GetPollInterval() time.Duration {
	if t.PollInterval <= 0 {
		return 5 * time.Second // default
	}
	return time.Duration(t.PollInterval) * time.Second
}

// LoadConfig loads test configuration from the specified file
func LoadConfig(configPath string) (*TestConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config TestConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// LoadConfigFromEnvOrFile loads config from environment variable path or default location
func LoadConfigFromEnvOrFile() (*TestConfig, error) {
	// Check environment variable first
	configPath := os.Getenv("LCM_TEST_CONFIG")
	if configPath == "" {
		// Default to testdata/dns_config.yaml relative to test directory
		configPath = filepath.Join("testdata", "dns_config.yaml")
	}

	return LoadConfig(configPath)
}

// Validate validates the test configuration
func (c *TestConfig) Validate() error {
	// Server config is required
	if c.Server.Address == "" {
		return fmt.Errorf("server.address is required")
	}
	if c.Server.CAFile == "" {
		return fmt.Errorf("server.ca_file is required")
	}
	if c.Server.SharedSecret == "" {
		return fmt.Errorf("server.shared_secret is required")
	}

	// ACME config validation (optional for self-signed tests)
	if c.ACME.Endpoint != "" {
		if c.ACME.Email == "" {
			return fmt.Errorf("acme.email is required when acme.endpoint is set")
		}
	}

	// DNS provider validation (optional for self-signed tests)
	if c.DNSProvider.Name != "" {
		if len(c.DNSProvider.Config) == 0 {
			return fmt.Errorf("dns_provider.config is required when dns_provider.name is set")
		}
	}

	// Test domain validation (optional for self-signed tests)
	if c.TestDomain.Domain != "" {
		if len(c.TestDomain.DNSNames) == 0 {
			return fmt.Errorf("test_domain.dns_names is required when test_domain.domain is set")
		}
	}

	return nil
}

// IsLetsEncryptStaging returns true if using Let's Encrypt staging
func (c *TestConfig) IsLetsEncryptStaging() bool {
	return c.ACME.Endpoint == "https://acme-staging-v02.api.letsencrypt.org/directory"
}

// IsLetsEncryptProduction returns true if using Let's Encrypt production
func (c *TestConfig) IsLetsEncryptProduction() bool {
	return c.ACME.Endpoint == "https://acme-v02.api.letsencrypt.org/directory"
}

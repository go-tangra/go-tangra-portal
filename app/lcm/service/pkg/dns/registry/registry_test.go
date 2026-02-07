package registry_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/registry"
	// Import to register providers
	_ "github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/init"
)

func TestGetProvider_RegisteredProviders(t *testing.T) {
	// Test that we can get each registered provider
	providers := registry.ListProviders()
	if len(providers) == 0 {
		t.Fatal("no providers registered")
	}

	t.Logf("Found %d registered providers: %v", len(providers), providers)

	// Expected providers
	expectedProviders := map[string]bool{
		"acmedns":      true,
		"cloudflare":   true,
		"clouddns":     true,
		"digitalocean": true,
		"easydns":      true,
		"gcloud":       true,
		"hurricane":    true,
		"httpreq":      true,
		"pdns":         true,
		"route53":      true,
	}

	// Check that all expected providers are registered
	for expectedProvider := range expectedProviders {
		found := false
		for _, provider := range providers {
			if provider == expectedProvider {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected provider %q not found in registered providers", expectedProvider)
		}
	}
}

func TestGetProvider_ValidConfigurations(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		config   map[string]string
	}{
		{
			name:     "cloudflare",
			provider: "cloudflare",
			config: map[string]string{
				"dnsApiToken": "test-token",
			},
		},
		{
			name:     "digitalocean",
			provider: "digitalocean",
			config: map[string]string{
				"authToken": "test-token",
			},
		},
		{
			name:     "route53",
			provider: "route53",
			config: map[string]string{
				"accessKeyId":     "test-access-key",
				"secretAccessKey": "test-secret-key",
				"region":          "us-east-1",
			},
		},
		{
			name:     "gcloud",
			provider: "gcloud",
			config: map[string]string{
				"project": "test-project",
			},
		},
		{
			name:     "pdns",
			provider: "pdns",
			config: map[string]string{
				"apiKey": "test-key",
				"host":   "http://localhost:8081",
			},
		},
		{
			name:     "hurricane",
			provider: "hurricane",
			config: map[string]string{
				"credentials": `{"example.com": "token123"}`,
			},
		},
		{
			name:     "httpreq",
			provider: "httpreq",
			config: map[string]string{
				"endpoint": "http://localhost:8080/dns",
			},
		},
		{
			name:     "easydns",
			provider: "easydns",
			config: map[string]string{
				"token": "test-token",
				"key":   "test-key",
			},
		},
		{
			name:     "clouddns",
			provider: "clouddns",
			config: map[string]string{
				"clientId": "test-client",
				"email":    "test@example.com",
				"password": "test-password",
			},
		},
		{
			name:     "acmedns",
			provider: "acmedns",
			config:   map[string]string{}, // No required fields
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := dns.GetProvider(tt.provider, tt.config)
			if err != nil {
				// We expect some providers to fail with auth errors, not config errors
				if strings.Contains(err.Error(), "configuration validation failed") ||
					strings.Contains(err.Error(), "is not registered") ||
					strings.Contains(err.Error(), "missing required fields") {
					t.Errorf("unexpected configuration error: %v", err)
				}
				// Other errors (auth, network) are acceptable in tests
			}
			
			if provider != nil && err == nil {
				t.Logf("Provider %q created successfully", tt.provider)
			}
		})
	}
}

func TestGetProvider_InvalidProvider(t *testing.T) {
	_, err := dns.GetProvider("nonexistent", map[string]string{})
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
	if !strings.Contains(err.Error(), "is not registered") {
		t.Errorf("expected 'not registered' error, got: %v", err)
	}
}

func TestGetProvider_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		provider      string
		config        map[string]string
		expectedError string
	}{
		{
			provider:      "cloudflare",
			config:        map[string]string{}, // Missing dnsApiToken
			expectedError: "missing required fields: dnsApiToken",
		},
		{
			provider:      "digitalocean",
			config:        map[string]string{}, // Missing authToken
			expectedError: "missing required fields: authToken",
		},
		{
			provider: "route53",
			config: map[string]string{
				"accessKeyId": "test", // Missing secretAccessKey and region
			},
			expectedError: "missing required fields: secretAccessKey, region",
		},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			_, err := dns.GetProvider(tt.provider, tt.config)
			if err == nil {
				t.Error("expected error for missing required fields")
				return
			}
			
			if !strings.Contains(err.Error(), "configuration validation failed") {
				t.Errorf("expected configuration validation error, got: %v", err)
			}
		})
	}
}

func TestGetProviderInfo(t *testing.T) {
	// Test getting info for existing provider
	info, err := registry.GetProviderInfo("cloudflare")
	if err != nil {
		t.Fatalf("failed to get provider info: %v", err)
	}

	if info.Name != "cloudflare" {
		t.Errorf("expected name 'cloudflare', got %q", info.Name)
	}

	if info.Description == "" {
		t.Error("expected non-empty description")
	}

	expectedRequired := []string{"dnsApiToken"}
	if !reflect.DeepEqual(info.RequiredFields, expectedRequired) {
		t.Errorf("expected required fields %v, got %v", expectedRequired, info.RequiredFields)
	}

	// Test getting info for nonexistent provider
	_, err = registry.GetProviderInfo("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}

func TestGetAllProviderInfo(t *testing.T) {
	allInfo := registry.GetAllProviderInfo()
	if len(allInfo) == 0 {
		t.Fatal("expected provider info for registered providers")
	}

	// Check a few specific providers
	if cloudflareInfo, exists := allInfo["cloudflare"]; exists {
		if cloudflareInfo.Name != "cloudflare" {
			t.Errorf("expected cloudflare name, got %q", cloudflareInfo.Name)
		}
	} else {
		t.Error("cloudflare provider info not found")
	}

	if gcloudInfo, exists := allInfo["gcloud"]; exists {
		if gcloudInfo.Name != "gcloud" {
			t.Errorf("expected gcloud name, got %q", gcloudInfo.Name)
		}
	} else {
		t.Error("gcloud provider info not found")
	}
}

func TestListProviders(t *testing.T) {
	providers := registry.ListProviders()
	if len(providers) == 0 {
		t.Fatal("expected at least one registered provider")
	}

	// Check that common providers are in the list
	expectedProviders := []string{"cloudflare", "route53", "digitalocean", "gcloud"}
	for _, expected := range expectedProviders {
		found := false
		for _, provider := range providers {
			if provider == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected provider %q not found in list", expected)
		}
	}
}

func TestConfigurationHelpers(t *testing.T) {
	config := map[string]string{
		"stringValue": "test-value",
		"emptyString": "",
		"intValue":    "42",
		"boolTrue":    "true",
		"boolFalse":   "false",
		"listValue":   "item1,item2, item3 ,item4",
		"jsonValue":   `{"key1":"value1","key2":"value2"}`,
		"invalidInt":  "not-a-number",
		"invalidBool": "not-a-boolean",
		"invalidJSON": `{"invalid":json}`,
	}

	// Test GetString
	if registry.GetString(config, "stringValue", "default") != "test-value" {
		t.Error("GetString failed for existing value")
	}
	if registry.GetString(config, "nonexistent", "default") != "default" {
		t.Error("GetString failed for default value")
	}
	if registry.GetString(config, "emptyString", "default") != "default" {
		t.Error("GetString should return default for empty string")
	}

	// Test GetInt32
	intVal, err := registry.GetInt32(config, "intValue", 0)
	if err != nil || intVal != 42 {
		t.Errorf("GetInt32 failed: %v, value: %d", err, intVal)
	}

	defaultInt, err := registry.GetInt32(config, "nonexistent", 100)
	if err != nil || defaultInt != 100 {
		t.Errorf("GetInt32 default failed: %v, value: %d", err, defaultInt)
	}

	_, err = registry.GetInt32(config, "invalidInt", 0)
	if err == nil {
		t.Error("GetInt32 should return error for invalid integer")
	}

	// Test GetBool
	boolVal, err := registry.GetBool(config, "boolTrue", false)
	if err != nil || !boolVal {
		t.Errorf("GetBool failed: %v, value: %t", err, boolVal)
	}

	boolVal, err = registry.GetBool(config, "boolFalse", true)
	if err != nil || boolVal {
		t.Errorf("GetBool failed: %v, value: %t", err, boolVal)
	}

	_, err = registry.GetBool(config, "invalidBool", false)
	if err == nil {
		t.Error("GetBool should return error for invalid boolean")
	}

	// Test GetStringSlice
	slice := registry.GetStringSlice(config, "listValue")
	expected := []string{"item1", "item2", "item3", "item4"}
	if !reflect.DeepEqual(slice, expected) {
		t.Errorf("GetStringSlice failed: expected %v, got %v", expected, slice)
	}

	// Test GetJSONMap
	jsonMap, err := registry.GetJSONMap(config, "jsonValue")
	if err != nil {
		t.Errorf("GetJSONMap failed: %v", err)
	}
	if jsonMap["key1"] != "value1" || jsonMap["key2"] != "value2" {
		t.Errorf("GetJSONMap failed: got %v", jsonMap)
	}

	_, err = registry.GetJSONMap(config, "invalidJSON")
	if err == nil {
		t.Error("GetJSONMap should return error for invalid JSON")
	}
}
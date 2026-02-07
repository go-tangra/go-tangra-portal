package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/challenge"
)

// ProviderFactory is a function that creates a DNS provider from configuration
type ProviderFactory func(config map[string]string) (challenge.Provider, error)

// ProviderInfo contains metadata about a DNS provider
type ProviderInfo struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	RequiredFields []string        `json:"requiredFields"`
	OptionalFields []string        `json:"optionalFields"`
	Factory        ProviderFactory `json:"-"`
}

// Registry holds all registered DNS providers
type Registry struct {
	mu        sync.RWMutex
	providers map[string]*ProviderInfo
}

// Global registry instance
var globalRegistry = &Registry{
	providers: make(map[string]*ProviderInfo),
}

// RegisterProvider registers a new DNS provider
func RegisterProvider(info *ProviderInfo) error {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	if info == nil {
		return errors.New("provider info cannot be nil")
	}

	if info.Name == "" {
		return errors.New("provider name cannot be empty")
	}

	if info.Factory == nil {
		return errors.New("provider factory function cannot be nil")
	}

	if _, exists := globalRegistry.providers[info.Name]; exists {
		return fmt.Errorf("provider %q is already registered", info.Name)
	}

	globalRegistry.providers[info.Name] = info
	return nil
}

// GetProvider creates a DNS provider instance by name and configuration
func GetProvider(name string, config map[string]string) (challenge.Provider, error) {
	globalRegistry.mu.RLock()
	info, exists := globalRegistry.providers[name]
	globalRegistry.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("DNS provider %q is not registered", name)
	}

	// Validate required fields
	if err := validateRequiredFields(info, config); err != nil {
		return nil, fmt.Errorf("configuration validation failed for provider %q: %w", name, err)
	}

	// Create the provider using the factory function
	provider, err := info.Factory(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider %q: %w", name, err)
	}

	return provider, nil
}

// ListProviders returns a list of all registered providers
func ListProviders() []string {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	names := make([]string, 0, len(globalRegistry.providers))
	for name := range globalRegistry.providers {
		names = append(names, name)
	}

	return names
}

// GetProviderInfo returns information about a registered provider
func GetProviderInfo(name string) (*ProviderInfo, error) {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	info, exists := globalRegistry.providers[name]
	if !exists {
		return nil, fmt.Errorf("DNS provider %q is not registered", name)
	}

	// Return a copy to prevent modification
	return &ProviderInfo{
		Name:           info.Name,
		Description:    info.Description,
		RequiredFields: append([]string(nil), info.RequiredFields...),
		OptionalFields: append([]string(nil), info.OptionalFields...),
	}, nil
}

// GetAllProviderInfo returns information about all registered providers
func GetAllProviderInfo() map[string]*ProviderInfo {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	result := make(map[string]*ProviderInfo)
	for name, info := range globalRegistry.providers {
		result[name] = &ProviderInfo{
			Name:           info.Name,
			Description:    info.Description,
			RequiredFields: append([]string(nil), info.RequiredFields...),
			OptionalFields: append([]string(nil), info.OptionalFields...),
		}
	}

	return result
}

// validateRequiredFields checks if all required fields are present in the configuration
func validateRequiredFields(info *ProviderInfo, config map[string]string) error {
	missing := make([]string, 0)

	for _, field := range info.RequiredFields {
		if value, exists := config[field]; !exists || strings.TrimSpace(value) == "" {
			missing = append(missing, field)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}

	return nil
}

// Helper functions for configuration parsing

// GetString gets a string value from config with optional default
func GetString(config map[string]string, key, defaultValue string) string {
	if value, exists := config[key]; exists && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return defaultValue
}

// GetInt32 gets an int32 value from config with optional default
func GetInt32(config map[string]string, key string, defaultValue int32) (int32, error) {
	value := GetString(config, key, "")
	if value == "" {
		return defaultValue, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return defaultValue, fmt.Errorf("invalid integer value for %s: %s", key, value)
	}

	return int32(parsed), nil
}

// GetBool gets a boolean value from config with optional default
func GetBool(config map[string]string, key string, defaultValue bool) (bool, error) {
	value := GetString(config, key, "")
	if value == "" {
		return defaultValue, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue, fmt.Errorf("invalid boolean value for %s: %s", key, value)
	}

	return parsed, nil
}

// GetStringSlice gets a string slice from config (comma-separated values)
func GetStringSlice(config map[string]string, key string) []string {
	value := GetString(config, key, "")
	if value == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// GetJSONMap gets a map from JSON string in config
func GetJSONMap(config map[string]string, key string) (map[string]string, error) {
	value := GetString(config, key, "")
	if value == "" {
		return nil, nil
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON for %s: %w", key, err)
	}

	return result, nil
}
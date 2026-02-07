package gcloud

import (
	"testing"
)

func TestChallengeProviderConfig_Validation(t *testing.T) {
	tests := []struct {
		name        string
		config      *ChallengeProviderConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorMsg:    "the configuration of the acme challenge provider is nil",
		},
		{
			name: "missing project",
			config: &ChallengeProviderConfig{
				ServiceAccountKey: `{"type": "service_account"}`,
			},
			expectError: true,
			errorMsg:    "google cloud project is required",
		},
		{
			name: "valid config with project only",
			config: &ChallengeProviderConfig{
				Project: "test-project",
			},
			expectError: false,
		},
		{
			name: "valid config with service account key",
			config: &ChallengeProviderConfig{
				Project:           "test-project",
				ServiceAccountKey: `{"type": "service_account", "project_id": "test-project"}`,
			},
			expectError: false,
		},
		{
			name: "valid config with service account file",
			config: &ChallengeProviderConfig{
				Project:            "test-project",
				ServiceAccountFile: "/path/to/service-account.json",
			},
			expectError: false,
		},
		{
			name: "complete config",
			config: &ChallengeProviderConfig{
				Project:                   "test-project",
				ZoneID:                    "test-zone",
				AllowPrivateZone:          true,
				ImpersonateServiceAccount: "test@example.com",
				DnsPropagationTimeout:     120,
				DnsPollingInterval:        10,
				DnsTTL:                    300,
				Debug:                     true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewChallengeProvider(tt.config)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if err.Error() != tt.errorMsg {
					t.Errorf("expected error message %q, got %q", tt.errorMsg, err.Error())
				}
			} else if err != nil {
				// For valid configs, we expect the error to be related to authentication/credentials
				// rather than configuration validation, so we just check it's not a validation error
				if err.Error() == "the configuration of the acme challenge provider is nil" ||
					err.Error() == "google cloud project is required" {
					t.Errorf("unexpected validation error: %v", err)
				}
				// Authentication errors are expected in tests without real credentials
			}
		})
	}
}

func TestChallengeProviderConfig_DefaultValues(t *testing.T) {
	config := &ChallengeProviderConfig{
		Project: "test-project",
	}

	// Test that the config can be created with minimal settings
	_, err := NewChallengeProvider(config)
	
	// We expect some error here since we don't have real GCloud credentials,
	// but it should not be a validation error
	if err != nil {
		validationErrors := []string{
			"the configuration of the acme challenge provider is nil",
			"google cloud project is required",
		}
		
		for _, validationError := range validationErrors {
			if err.Error() == validationError {
				t.Errorf("unexpected validation error with minimal config: %v", err)
			}
		}
	}
}
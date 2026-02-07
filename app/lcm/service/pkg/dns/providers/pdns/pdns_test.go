package pdns

import "testing"

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
			name:        "missing API key",
			config:      &ChallengeProviderConfig{Host: "http://localhost:8081"},
			expectError: true,
			errorMsg:    "powerDNS API key is required",
		},
		{
			name:        "missing host",
			config:      &ChallengeProviderConfig{APIKey: "test-key"},
			expectError: true,
			errorMsg:    "powerDNS host is required",
		},
		{
			name: "invalid host URL",
			config: &ChallengeProviderConfig{
				APIKey: "test-key",
				Host:   "://invalid-url",
			},
			expectError: true,
			errorMsg:    "invalid powerDNS host URL",
		},
		{
			name: "valid minimal config",
			config: &ChallengeProviderConfig{
				APIKey: "test-key",
				Host:   "http://localhost:8081",
			},
			expectError: false,
		},
		{
			name: "complete config",
			config: &ChallengeProviderConfig{
				APIKey:                "test-key",
				Host:                  "http://localhost:8081",
				ServerName:            "localhost",
				APIVersion:            1,
				DnsPropagationTimeout: 120,
				DnsPollingInterval:    10,
				DnsTTL:                300,
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
				// For valid configs, we might get connection errors, which are acceptable
				validationErrors := []string{
					"the configuration of the acme challenge provider is nil",
					"powerDNS API key is required",
					"powerDNS host is required",
					"invalid powerDNS host URL",
				}
				
				for _, validationError := range validationErrors {
					if err.Error() == validationError {
						t.Errorf("unexpected validation error: %v", err)
					}
				}
			}
		})
	}
}
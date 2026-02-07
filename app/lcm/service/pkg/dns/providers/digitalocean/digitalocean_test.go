package digitalocean

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
			name:        "missing auth token",
			config:      &ChallengeProviderConfig{},
			expectError: true,
			errorMsg:    "digitalOcean auth token is required",
		},
		{
			name: "valid minimal config",
			config: &ChallengeProviderConfig{
				AuthToken: "test-token",
			},
			expectError: false,
		},
		{
			name: "complete config",
			config: &ChallengeProviderConfig{
				AuthToken:             "test-token",
				BaseURL:               "https://api.digitalocean.com",
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
				// For valid configs, we might get auth errors, which are acceptable
				validationErrors := []string{
					"the configuration of the acme challenge provider is nil",
					"digitalOcean auth token is required",
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
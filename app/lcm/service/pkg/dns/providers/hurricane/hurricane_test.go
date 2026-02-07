package hurricane

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
			name:        "empty credentials",
			config:      &ChallengeProviderConfig{},
			expectError: true,
			errorMsg:    "hurricane Electric credentials are required (at least one domain-token pair)",
		},
		{
			name: "empty domain in credentials",
			config: &ChallengeProviderConfig{
				Credentials: map[string]string{"": "token"},
			},
			expectError: true,
			errorMsg:    "hurricane Electric credential domain cannot be empty",
		},
		{
			name: "empty token in credentials",
			config: &ChallengeProviderConfig{
				Credentials: map[string]string{"example.com": ""},
			},
			expectError: true,
			errorMsg:    "hurricane Electric credential token cannot be empty",
		},
		{
			name: "valid minimal config",
			config: &ChallengeProviderConfig{
				Credentials: map[string]string{"example.com": "token123"},
			},
			expectError: false,
		},
		{
			name: "complete config",
			config: &ChallengeProviderConfig{
				Credentials: map[string]string{
					"example.com":           "token123",
					"subdomain.example.com": "token456",
				},
				DnsPropagationTimeout: 120,
				DnsPollingInterval:    10,
				DnsSequenceInterval:   5,
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
					"hurricane Electric credentials are required (at least one domain-token pair)",
					"hurricane Electric credential domain cannot be empty",
					"hurricane Electric credential token cannot be empty",
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
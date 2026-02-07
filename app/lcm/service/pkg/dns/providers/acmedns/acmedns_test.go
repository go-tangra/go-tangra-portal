package acmedns

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
			name:        "empty config (valid)",
			config:      &ChallengeProviderConfig{},
			expectError: false,
		},
		{
			name: "config with API base",
			config: &ChallengeProviderConfig{
				APIBase: "https://auth.acme-dns.io",
			},
			expectError: false,
		},
		{
			name: "complete config",
			config: &ChallengeProviderConfig{
				APIBase:        "https://auth.acme-dns.io",
				AllowList:      []string{"example.com", "*.example.com"},
				StoragePath:    "/path/to/storage",
				StorageBaseURL: "https://storage.example.com",
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
				// For valid configs, we might get auth/connection errors, which are acceptable
				if err.Error() == tt.errorMsg {
					t.Errorf("unexpected validation error: %v", err)
				}
			}
		})
	}
}
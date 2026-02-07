package crypto

import (
	"fmt"

	pkgCrypto "github.com/go-tangra/go-tangra-portal/pkg/crypto"
)

// PrivateKeyEncryptor handles encryption/decryption of private keys for LCM
type PrivateKeyEncryptor struct {
	encryptor *pkgCrypto.Encryptor
	enabled   bool
}

// NewPrivateKeyEncryptor creates a new encryptor using the shared secret
// If sharedSecret is empty, encryption is disabled (pass-through mode)
func NewPrivateKeyEncryptor(sharedSecret string) (*PrivateKeyEncryptor, error) {
	if sharedSecret == "" {
		return &PrivateKeyEncryptor{enabled: false}, nil
	}

	// Derive encryption key from shared_secret with salt
	// This ensures the encryption key differs from the shared secret itself
	key := "lcm-private-key-" + sharedSecret

	encryptor, err := pkgCrypto.NewEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &PrivateKeyEncryptor{
		encryptor: encryptor,
		enabled:   true,
	}, nil
}

// Encrypt encrypts a private key PEM
// Returns the encrypted string prefixed with "enc:" or the original if encryption is disabled
func (e *PrivateKeyEncryptor) Encrypt(privateKeyPEM string) (string, error) {
	if !e.enabled || privateKeyPEM == "" {
		return privateKeyPEM, nil
	}
	return e.encryptor.Encrypt(privateKeyPEM)
}

// Decrypt decrypts a private key PEM
// Handles both encrypted (prefixed with "enc:") and plaintext data for backward compatibility
func (e *PrivateKeyEncryptor) Decrypt(encryptedPEM string) (string, error) {
	if !e.enabled || encryptedPEM == "" {
		return encryptedPEM, nil
	}
	return e.encryptor.Decrypt(encryptedPEM)
}

// IsEnabled returns whether encryption is enabled
func (e *PrivateKeyEncryptor) IsEnabled() bool {
	return e.enabled
}

// IsEncrypted checks if the data is encrypted (has the "enc:" prefix)
func IsEncrypted(data string) bool {
	return pkgCrypto.IsEncrypted(data)
}

package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// KVStore provides KV v2 operations for password storage
type KVStore struct {
	client *Client
}

// NewKVStore creates a new KV store
func NewKVStore(client *Client) *KVStore {
	return &KVStore{client: client}
}

// SecretData represents secret data stored in Vault
type SecretData struct {
	Password string            `json:"password"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// VersionInfo represents version information from Vault
type VersionInfo struct {
	Version   int
	CreatedAt string
	DeletedAt string
	Destroyed bool
}

// BuildPath constructs the Vault path for a secret
func (s *KVStore) BuildPath(tenantID uint32, secretID string) string {
	return fmt.Sprintf("warden/%d/%s", tenantID, secretID)
}

// BuildVersionPath constructs the Vault path for a specific version
func (s *KVStore) BuildVersionPath(tenantID uint32, secretID string, version int) string {
	return fmt.Sprintf("warden/%d/%s/v%d", tenantID, secretID, version)
}

// StorePassword stores a password in Vault KV v2
// Returns the version number created
func (s *KVStore) StorePassword(ctx context.Context, path, password string, metadata map[string]string) (int, error) {
	data := map[string]any{
		"password": password,
	}
	if metadata != nil {
		data["metadata"] = metadata
	}

	// Use KV v2 API
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	secret, err := kv.Put(ctx, path, data)
	if err != nil {
		return 0, fmt.Errorf("failed to store password in Vault: %w", err)
	}

	version := 1
	if secret != nil && secret.VersionMetadata != nil {
		version = secret.VersionMetadata.Version
	}

	s.client.log.Debugf("Stored password at path %s, version %d", path, version)
	return version, nil
}

// GetPassword retrieves the current password from Vault
func (s *KVStore) GetPassword(ctx context.Context, path string) (string, int, error) {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	secret, err := kv.Get(ctx, path)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get password from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", 0, fmt.Errorf("no secret data found at path: %s", path)
	}

	password, ok := secret.Data["password"].(string)
	if !ok {
		return "", 0, fmt.Errorf("password field not found or invalid type")
	}

	version := 0
	if secret.VersionMetadata != nil {
		version = secret.VersionMetadata.Version
	}

	return password, version, nil
}

// GetPasswordVersion retrieves a specific version of the password from Vault
func (s *KVStore) GetPasswordVersion(ctx context.Context, path string, version int) (string, error) {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	secret, err := kv.GetVersion(ctx, path, version)
	if err != nil {
		return "", fmt.Errorf("failed to get password version %d from Vault: %w", version, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no secret data found at path %s version %d", path, version)
	}

	password, ok := secret.Data["password"].(string)
	if !ok {
		return "", fmt.Errorf("password field not found or invalid type")
	}

	return password, nil
}

// DeletePassword soft-deletes the latest version of a password
func (s *KVStore) DeletePassword(ctx context.Context, path string) error {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	if err := kv.Delete(ctx, path); err != nil {
		return fmt.Errorf("failed to delete password from Vault: %w", err)
	}

	s.client.log.Debugf("Deleted password at path %s", path)
	return nil
}

// DeletePasswordVersions soft-deletes specific versions
func (s *KVStore) DeletePasswordVersions(ctx context.Context, path string, versions []int) error {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	if err := kv.DeleteVersions(ctx, path, versions); err != nil {
		return fmt.Errorf("failed to delete password versions from Vault: %w", err)
	}

	s.client.log.Debugf("Deleted password versions %v at path %s", versions, path)
	return nil
}

// DestroyPassword permanently destroys a password (cannot be recovered)
func (s *KVStore) DestroyPassword(ctx context.Context, path string, versions []int) error {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	if err := kv.Destroy(ctx, path, versions); err != nil {
		return fmt.Errorf("failed to destroy password in Vault: %w", err)
	}

	s.client.log.Debugf("Destroyed password versions %v at path %s", versions, path)
	return nil
}

// DestroyAllVersions permanently destroys all versions and metadata
func (s *KVStore) DestroyAllVersions(ctx context.Context, path string) error {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	if err := kv.DeleteMetadata(ctx, path); err != nil {
		return fmt.Errorf("failed to destroy all password versions in Vault: %w", err)
	}

	s.client.log.Debugf("Destroyed all versions at path %s", path)
	return nil
}

// UndeletePassword recovers soft-deleted versions
func (s *KVStore) UndeletePassword(ctx context.Context, path string, versions []int) error {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	if err := kv.Undelete(ctx, path, versions); err != nil {
		return fmt.Errorf("failed to undelete password versions from Vault: %w", err)
	}

	s.client.log.Debugf("Undeleted password versions %v at path %s", versions, path)
	return nil
}

// ListVersions returns version information for a secret
func (s *KVStore) ListVersions(ctx context.Context, path string) ([]VersionInfo, error) {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	metadata, err := kv.GetMetadata(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get version metadata from Vault: %w", err)
	}

	if metadata == nil || metadata.Versions == nil {
		return nil, nil
	}

	versions := make([]VersionInfo, 0, len(metadata.Versions))
	for versionStr, versionMeta := range metadata.Versions {
		version, _ := strconv.Atoi(versionStr)
		info := VersionInfo{
			Version:   version,
			Destroyed: versionMeta.Destroyed,
		}
		if !versionMeta.CreatedTime.IsZero() {
			info.CreatedAt = versionMeta.CreatedTime.Format("2006-01-02T15:04:05Z")
		}
		if !versionMeta.DeletionTime.IsZero() {
			info.DeletedAt = versionMeta.DeletionTime.Format("2006-01-02T15:04:05Z")
		}
		versions = append(versions, info)
	}

	return versions, nil
}

// GetCurrentVersion returns the current version number for a secret
func (s *KVStore) GetCurrentVersion(ctx context.Context, path string) (int, error) {
	kv := s.client.GetClient().KVv2(s.client.GetMountPath())

	metadata, err := kv.GetMetadata(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("failed to get metadata from Vault: %w", err)
	}

	if metadata == nil {
		return 0, nil
	}

	return metadata.CurrentVersion, nil
}

// CalculateChecksum calculates SHA-256 checksum of a password
func CalculateChecksum(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

package data

import (
	"os"

	"github.com/redis/go-redis/v9"

	"github.com/tx7do/kratos-bootstrap/bootstrap"
	redisClient "github.com/tx7do/kratos-bootstrap/cache/redis"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/pkg/vault"
)

// NewRedisClient creates a Redis client
func NewRedisClient(ctx *bootstrap.Context) (*redis.Client, func(), error) {
	cfg := ctx.GetConfig()
	if cfg == nil {
		return nil, func() {}, nil
	}

	l := ctx.NewLoggerHelper("redis/data/warden-service")

	cli := redisClient.NewClient(cfg.Data, l)

	return cli, func() {
		if err := cli.Close(); err != nil {
			l.Error(err)
		}
	}, nil
}

// VaultConfig holds Vault configuration from app config
type VaultConfig struct {
	Address      string `json:"address" yaml:"address"`
	RoleID       string `json:"role_id" yaml:"role_id"`
	SecretID     string `json:"secret_id" yaml:"secret_id"`
	MountPath    string `json:"mount_path" yaml:"mount_path"`
	Namespace    string `json:"namespace" yaml:"namespace"`
}

// NewVaultClient creates a HashiCorp Vault client
func NewVaultClient(ctx *bootstrap.Context) (*vault.Client, func(), error) {
	l := ctx.NewLoggerHelper("vault/data/warden-service")

	// Get Vault config from environment or config file
	cfg := &vault.Config{
		Address:   getEnvOrDefault("VAULT_ADDR", "http://localhost:8200"),
		RoleID:    getEnvOrDefault("VAULT_ROLE_ID", ""),
		SecretID:  getEnvOrDefault("VAULT_SECRET_ID", ""),
		MountPath: getEnvOrDefault("VAULT_MOUNT_PATH", "secret"),
		Namespace: getEnvOrDefault("VAULT_NAMESPACE", ""),
	}

	client, err := vault.NewClient(cfg, ctx.GetLogger())
	if err != nil {
		l.Errorf("failed to create Vault client: %v", err)
		return nil, func() {}, err
	}

	return client, func() {
		if err := client.Close(); err != nil {
			l.Error(err)
		}
	}, nil
}

// NewVaultKVStore creates a Vault KV store
func NewVaultKVStore(client *vault.Client) *vault.KVStore {
	return vault.NewKVStore(client)
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

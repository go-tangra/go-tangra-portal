package data

import (
	"os"

	"github.com/redis/go-redis/v9"

	"github.com/tx7do/kratos-bootstrap/bootstrap"
	redisClient "github.com/tx7do/kratos-bootstrap/cache/redis"
)

// NewRedisClient creates a Redis client
func NewRedisClient(ctx *bootstrap.Context) (*redis.Client, func(), error) {
	cfg := ctx.GetConfig()
	if cfg == nil {
		return nil, func() {}, nil
	}

	l := ctx.NewLoggerHelper("redis/data/paperless-service")

	cli := redisClient.NewClient(cfg.Data, l)

	return cli, func() {
		if err := cli.Close(); err != nil {
			l.Error(err)
		}
	}, nil
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

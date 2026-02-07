package data

import (
	"github.com/redis/go-redis/v9"

	"github.com/tx7do/kratos-bootstrap/bootstrap"
	redisClient "github.com/tx7do/kratos-bootstrap/cache/redis"
)

// NewRedisClient creates a new Redis client
func NewRedisClient(ctx *bootstrap.Context) (*redis.Client, func(), error) {
	cfg := ctx.GetConfig()
	l := ctx.NewLoggerHelper("redis/data/ipam-service")

	cli := redisClient.NewClient(cfg.Data, l)

	return cli, func() {
		if err := cli.Close(); err != nil {
			l.Error(err)
		}
	}, nil
}

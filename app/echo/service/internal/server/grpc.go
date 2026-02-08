package server

import (
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	"github.com/go-tangra/go-tangra-portal/app/echo/service/internal/service"

	echopb "github.com/go-tangra/go-tangra-portal/api/gen/go/echo/service/v1"
)

// Config holds the server configuration
type Config struct {
	Addr    string
	Timeout string
}

// NewGRPCServer creates a new gRPC server for the Echo service
func NewGRPCServer(logger log.Logger, echoService *service.EchoService, cfg *Config) *grpc.Server {
	opts := []grpc.ServerOption{
		grpc.Middleware(
			recovery.Recovery(),
			logging.Server(logger),
		),
	}

	if cfg.Addr != "" {
		opts = append(opts, grpc.Address(cfg.Addr))
	}

	srv := grpc.NewServer(opts...)

	// Register the Echo service using the generated registration function
	echopb.RegisterEchoServiceServer(srv, echoService)

	return srv
}

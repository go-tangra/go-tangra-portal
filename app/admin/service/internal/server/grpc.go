package server

import (
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/service"
	customLogging "github.com/go-tangra/go-tangra-portal/pkg/middleware/logging"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// NewGRPCMiddleware creates gRPC middleware
func NewGRPCMiddleware(logger log.Logger) []middleware.Middleware {
	var ms []middleware.Middleware
	ms = append(ms, recovery.Recovery())
	// Use custom redacted logging middleware that respects protobuf Redact() methods
	ms = append(ms, customLogging.RedactedServer(logger))
	return ms
}

// NewGRPCServer creates a new gRPC server for module registration.
// This server handles:
// - Module registration/unregistration from dynamic modules
// - Module heartbeats
// - Module listing (for admin UI)
func NewGRPCServer(
	ctx *bootstrap.Context,
	moduleRegistrationService *service.ModuleRegistrationService,
	commonModuleRegistrationAdapter *service.CommonModuleRegistrationAdapter,
) *grpc.Server {
	cfg := ctx.GetConfig()
	logger := ctx.GetLogger()

	l := log.NewHelper(log.With(logger, "module", "server/grpc"))

	// Create gRPC server options
	opts := []grpc.ServerOption{
		grpc.Middleware(NewGRPCMiddleware(logger)...),
	}

	// Add server configuration from bootstrap config
	if cfg.Server != nil && cfg.Server.Grpc != nil {
		if cfg.Server.Grpc.Addr != "" {
			opts = append(opts, grpc.Address(cfg.Server.Grpc.Addr))
		}
		if cfg.Server.Grpc.Timeout != nil {
			opts = append(opts, grpc.Timeout(cfg.Server.Grpc.Timeout.AsDuration()))
		}
	}

	// Create the gRPC server
	srv := grpc.NewServer(opts...)

	// Register the module registration service (admin.service.v1)
	adminV1.RegisterModuleRegistrationServiceServer(srv, moduleRegistrationService)

	// Register the common module registration service (common.service.v1)
	// This allows modules using the common proto to register with the admin service
	commonV1.RegisterModuleRegistrationServiceServer(srv, commonModuleRegistrationAdapter)

	l.Info("gRPC server configured with ModuleRegistrationService (admin.v1 and common.v1)")

	return srv
}

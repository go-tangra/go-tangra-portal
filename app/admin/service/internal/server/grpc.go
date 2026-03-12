package server

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	"github.com/tx7do/kratos-bootstrap/bootstrap"

	commonCert "github.com/go-tangra/go-tangra-common/cert"
	"github.com/go-tangra/go-tangra-common/middleware/mtls"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/metrics"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/service"
	appViewer "github.com/go-tangra/go-tangra-portal/pkg/entgo/viewer"
	customLogging "github.com/go-tangra/go-tangra-portal/pkg/middleware/logging"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// systemViewerMiddleware injects a system viewer context for all gRPC requests.
// The gRPC port is internal (service-to-service only), so all calls get system-level access.
func systemViewerMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			ctx = appViewer.NewSystemViewerContext(ctx)
			return handler(ctx, req)
		}
	}
}

// NewGRPCMiddleware creates gRPC middleware
func NewGRPCMiddleware(logger log.Logger, tlsEnabled bool, collector *metrics.Collector) []middleware.Middleware {
	var ms []middleware.Middleware
	ms = append(ms, recovery.Recovery())
	ms = append(ms, collector.Middleware())
	ms = append(ms, systemViewerMiddleware())

	if tlsEnabled {
		ms = append(ms, mtls.MTLSMiddleware(
			logger,
			mtls.WithPublicEndpoints(
				"/grpc.health.v1.Health/Check",
				"/grpc.health.v1.Health/Watch",
			),
		))
	}

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
	collector *metrics.Collector,
	moduleRegistrationService *service.ModuleRegistrationService,
	commonModuleRegistrationAdapter *service.CommonModuleRegistrationAdapter,
	userService *service.UserService,
	roleService *service.RoleService,
) (*grpc.Server, error) {
	cfg := ctx.GetConfig()
	logger := ctx.GetLogger()

	l := log.NewHelper(log.With(logger, "module", "server/grpc"))

	tlsEnabled := false

	// Try to initialize CertManager for mTLS
	certManager, err := commonCert.NewCertManager(ctx, "ADMIN")
	if err != nil {
		l.Warnf("CertManager initialization failed: %v, running without mTLS", err)
	}

	// Create gRPC server options
	opts := []grpc.ServerOption{
		grpc.Middleware(NewGRPCMiddleware(logger, tlsEnabled, collector)...),
	}

	// Configure mTLS if certificates are available
	if certManager != nil && certManager.IsTLSEnabled() {
		tlsConfig, err := certManager.GetServerTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("mTLS required but failed to load TLS config: %w", err)
		}
		opts = append(opts, grpc.TLSConfig(tlsConfig))
		tlsEnabled = true
		l.Info("gRPC server configured with mTLS")

		// Rebuild middleware with mTLS enabled
		opts[0] = grpc.Middleware(NewGRPCMiddleware(logger, tlsEnabled, collector)...)
	} else {
		l.Warn("TLS not enabled, gRPC server running without mTLS")
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

	// Register the user service so modules can call it via gRPC
	adminV1.RegisterUserServiceServer(srv, userService)

	// Register the role service so modules can call it via gRPC
	adminV1.RegisterRoleServiceServer(srv, roleService)

	l.Info("gRPC server configured with ModuleRegistrationService (admin.v1 and common.v1), UserService, and RoleService")

	return srv, nil
}

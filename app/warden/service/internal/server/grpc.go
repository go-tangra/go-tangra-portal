package server

import (
	"context"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/metadata"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/middleware/validate"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/cert"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/service"

	appViewer "github.com/go-tangra/go-tangra-portal/pkg/entgo/viewer"
	"github.com/go-tangra/go-tangra-portal/pkg/middleware/audit"
	"github.com/go-tangra/go-tangra-portal/pkg/middleware/mtls"
)

// systemViewerMiddleware injects system viewer context for all requests
// This allows the warden service to bypass tenant privacy checks
func systemViewerMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			ctx = appViewer.NewSystemViewerContext(ctx)
			return handler(ctx, req)
		}
	}
}

// NewGRPCServer creates a gRPC server with mTLS and audit logging
func NewGRPCServer(
	ctx *bootstrap.Context,
	certManager *cert.CertManager,
	auditLogRepo *data.AuditLogRepo,
	folderSvc *service.FolderService,
	secretSvc *service.SecretService,
	permissionSvc *service.PermissionService,
	systemSvc *service.SystemService,
	bitwardenTransferSvc *service.BitwardenTransferService,
) *grpc.Server {
	cfg := ctx.GetConfig()
	l := ctx.NewLoggerHelper("warden/grpc")

	var opts []grpc.ServerOption

	// Get gRPC server configuration
	if cfg.Server != nil && cfg.Server.Grpc != nil {
		if cfg.Server.Grpc.Network != "" {
			opts = append(opts, grpc.Network(cfg.Server.Grpc.Network))
		}
		if cfg.Server.Grpc.Addr != "" {
			opts = append(opts, grpc.Address(cfg.Server.Grpc.Addr))
		}
		if cfg.Server.Grpc.Timeout != nil {
			opts = append(opts, grpc.Timeout(cfg.Server.Grpc.Timeout.AsDuration()))
		}
	}

	// Configure TLS if certificates are available
	if certManager != nil && certManager.IsTLSEnabled() {
		tlsConfig, err := certManager.GetServerTLSConfig()
		if err != nil {
			l.Warnf("Failed to get TLS config, running without TLS: %v", err)
		} else {
			opts = append(opts, grpc.TLSConfig(tlsConfig))
			l.Info("gRPC server configured with mTLS")
		}
	} else {
		l.Warn("TLS not enabled, running without mTLS")
	}

	// Add middleware
	var ms []middleware.Middleware
	ms = append(ms, recovery.Recovery())
	ms = append(ms, systemViewerMiddleware()) // Inject system viewer for ENT privacy
	ms = append(ms, tracing.Server())
	ms = append(ms, metadata.Server())
	ms = append(ms, logging.Server(ctx.GetLogger()))

	// Add mTLS middleware to extract client info from certificates
	ms = append(ms, mtls.MTLSMiddleware(
		ctx.GetLogger(),
		mtls.WithPublicEndpoints(
			"/grpc.health.v1.Health/Check",
			"/grpc.health.v1.Health/Watch",
		),
	))

	// Add audit logging middleware
	ms = append(ms, audit.Server(
		ctx.GetLogger(),
		audit.WithServiceName("warden-service"),
		audit.WithWriteAuditLogFunc(func(ctx context.Context, log *audit.AuditLog) error {
			return auditLogRepo.CreateFromEntry(ctx, log.ToEntry())
		}),
		audit.WithSkipOperations(
			"/grpc.health.v1.Health/Check",
			"/grpc.health.v1.Health/Watch",
		),
	))

	ms = append(ms, validate.Validator())

	opts = append(opts, grpc.Middleware(ms...))

	// Create gRPC server
	srv := grpc.NewServer(opts...)

	// Register services
	wardenV1.RegisterWardenFolderServiceServer(srv, folderSvc)
	wardenV1.RegisterWardenSecretServiceServer(srv, secretSvc)
	wardenV1.RegisterWardenPermissionServiceServer(srv, permissionSvc)
	wardenV1.RegisterWardenSystemServiceServer(srv, systemSvc)
	wardenV1.RegisterWardenBitwardenTransferServiceServer(srv, bitwardenTransferSvc)

	return srv
}

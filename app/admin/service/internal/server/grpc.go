package server

import (
	"context"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-common/grpcx"
	"github.com/go-tangra/go-tangra-common/middleware/mtls"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/metrics"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/service"
	appViewer "github.com/go-tangra/go-tangra-portal/pkg/entgo/viewer"
	customLogging "github.com/go-tangra/go-tangra-portal/pkg/middleware/logging"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
	authenticationV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/authentication/service/v1"
	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// moduleSecretPublicOps never require the shared secret (liveness probes).
var moduleSecretPublicOps = map[string]bool{
	"/grpc.health.v1.Health/Check": true,
	"/grpc.health.v1.Health/Watch": true,
}

// moduleSecretMiddleware authenticates callers of the plaintext :7787 control
// plane with the shared module-bootstrap secret. That port carries module
// registration AND the internal user/role/credential RPCs, and is reachable
// across hosts, so it must not rely on network isolation alone.
//
// Mode (env REGISTRATION_SECRET_MODE) controls rollout:
//
//	off     - disabled (legacy behaviour)
//	warn    - log violations but allow (default; safe while modules are
//	          redeployed with the secret-sending client)
//	enforce - reject callers that do not present the correct secret
//
// The secret comes from MODULE_BOOTSTRAP_SECRET — the same value modules use
// for LCM cert bootstrap.
func moduleSecretMiddleware(logger log.Logger) middleware.Middleware {
	l := log.NewHelper(log.With(logger, "module", "server/module-secret"))
	secret := grpcx.ModuleBootstrapSecret()
	mode := os.Getenv("REGISTRATION_SECRET_MODE")
	if mode == "" {
		mode = "warn"
	}

	if mode == "enforce" && secret == "" {
		// Fail closed rather than silently accept everyone.
		l.Error("REGISTRATION_SECRET_MODE=enforce but MODULE_BOOTSTRAP_SECRET is empty; all module calls will be rejected")
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if mode == "off" {
				return handler(ctx, req)
			}
			op := ""
			if tr, ok := transport.FromServerContext(ctx); ok {
				op = tr.Operation()
			}
			if moduleSecretPublicOps[op] {
				return handler(ctx, req)
			}
			if grpcx.ValidateModuleSecret(ctx, secret) {
				return handler(ctx, req)
			}
			if mode == "enforce" {
				l.Warnf("rejected unauthenticated call to %s on :7787 (missing/invalid module secret)", op)
				return nil, grpcstatus.Error(grpccodes.Unauthenticated, "module secret required")
			}
			// warn mode: record but allow, so a not-yet-updated module keeps working.
			l.Warnf("call to %s on :7787 lacks a valid module secret (allowed: mode=warn)", op)
			return handler(ctx, req)
		}
	}
}

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
	// Authenticate the caller BEFORE granting system-level access below.
	ms = append(ms, moduleSecretMiddleware(logger))
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
	userCredentialService *service.UserCredentialService,
) (*grpc.Server, error) {
	cfg := ctx.GetConfig()
	logger := ctx.GetLogger()

	l := log.NewHelper(log.With(logger, "module", "server/grpc"))

	// admin-service's inbound :7787 gRPC port is plaintext: every
	// module dials it with REGISTRATION_INSECURE=1 to send Register /
	// Heartbeat / Unregister. Adding TLS here breaks that bootstrap
	// path (modules can't yet have a CA-rooted cert chain to admin
	// since admin *is* the gateway they're registering with). Inbound
	// auth happens at the application layer via AuthToken in the RPC
	// body; outbound admin → module mTLS is what cert.Ensure below is
	// for. Hardcode tlsEnabled=false; cert.Ensure runs in main() before
	// the wire graph builds the transcoder, which needs the certs at
	// construction time.
	tlsEnabled := false

	// Create gRPC server options
	opts := []grpc.ServerOption{
		grpc.Middleware(NewGRPCMiddleware(logger, tlsEnabled, collector)...),
	}
	l.Info("gRPC server :7787 running plaintext (registration channel; module auth via AuthToken in body)")

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

	// Register the user credential service so modules (e.g. executor) can verify
	// a user's password before privileged content updates.
	authenticationV1.RegisterUserCredentialServiceServer(srv, userCredentialService)

	l.Info("gRPC server configured with ModuleRegistrationService (admin.v1 and common.v1), UserService, RoleService, and UserCredentialService")

	return srv, nil
}

package server

import (
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	authnEngine "github.com/tx7do/kratos-authn/engine"

	"github.com/go-tangra/go-tangra-common/gateway"
	gatewayTranscoder "github.com/go-tangra/go-tangra-common/gateway/transcoder"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/service"
)

// NewGatewayDynamicRouter creates a gateway.DynamicRouter wired with portal-specific adapters.
// This replaces the old server.NewDynamicRouter constructor.
func NewGatewayDynamicRouter(
	ctx *bootstrap.Context,
	registry *service.ModuleRegistry,
	authenticator authnEngine.Authenticator,
	apiAuditLogRepo *data.ApiAuditLogRepo,
) *gateway.DynamicRouter {
	logger := ctx.NewLoggerHelper("gateway/admin-service")

	// Create portal-specific adapters
	authAdapter := NewAuthContextAdapter()
	auditAdapter := NewAuditLogAdapter(logger, apiAuditLogRepo)
	registryAdapter := NewModuleRegistryAdapter(registry)

	// Create transcoder components
	descParser := gatewayTranscoder.NewDescriptorParser(logger)
	requestBuilder := gatewayTranscoder.NewRequestBuilder(logger)
	responseTransformer := gatewayTranscoder.NewResponseTransformer(logger)

	// Create transcoder with portal adapters
	tc := gatewayTranscoder.NewTranscoder(
		logger,
		descParser,
		requestBuilder,
		responseTransformer,
		authAdapter,
		gatewayTranscoder.WithAuditLogWriter(auditAdapter),
	)

	// Create and return the dynamic router
	return gateway.NewDynamicRouter(
		logger,
		tc,
		registryAdapter,
		authenticator,
	)
}

// compile-time interface checks
var _ gatewayTranscoder.AuthContextProvider = (*AuthContextAdapter)(nil)
var _ gatewayTranscoder.AuditLogWriter = (*AuditLogAdapter)(nil)
var _ gateway.ModuleRegistry = (*ModuleRegistryAdapter)(nil)

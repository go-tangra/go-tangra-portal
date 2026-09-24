// Package grpcapi mounts the gateway.v1 Registry service on the Freya gRPC
// server. Callers are modules on the mTLS channel; the Freya policy decides
// who may call, the registry decides what they may register.
package grpcapi

import (
	"google.golang.org/grpc"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
)

// Register mounts the Registry service; nil installs the Unimplemented stub
// so every method exists (and is policed) from the first start.
func Register(s grpc.ServiceRegistrar, h gatewayv1.RegistryServer) {
	if h == nil {
		h = gatewayv1.UnimplementedRegistryServer{}
	}
	gatewayv1.RegisterRegistryServer(s, h)
}

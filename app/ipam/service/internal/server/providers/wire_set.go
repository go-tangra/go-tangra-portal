//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

// This file defines the dependency injection ProviderSet for the server layer.

package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/cert"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/server"
)

var ProviderSet = wire.NewSet(
	cert.NewCertManager,
	server.NewGRPCServer,
)

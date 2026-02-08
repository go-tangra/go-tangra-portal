//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

// This file holds Wire provider setup used only by the Wire code generator.
// The build tag `wireinject` ensures this file is excluded from normal `go build`/final binaries.
// The generated file (e.g. `wire_gen.go`) does not have this tag and will be included in the final build.

package main

import (
	"github.com/google/wire"

	"github.com/go-kratos/kratos/v2"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	bootstrapProviders "github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/bootstrap/providers"
	dataProviders "github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data/providers"
	serverProviders "github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/server/providers"
	serviceProviders "github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/service/providers"
)

// initApp initializes the Wire provider entry for the kratos application.
//
// Parameters:
//   - *bootstrap.Context: *bootstrap.Context: bootstrap context
//
// Returns:
//   - *kratos.App: *kratos.App: constructed application instance
//   - func(): func(): cleanup function to run on shutdown
//   - error: error: possible construction error
func initApp(*bootstrap.Context) (*kratos.App, func(), error) {
	panic(
		wire.Build(
			dataProviders.ProviderSet,
			bootstrapProviders.ProviderSet,
			serverProviders.ProviderSet,
			serviceProviders.ProviderSet,
			newApp,
		),
	)
}

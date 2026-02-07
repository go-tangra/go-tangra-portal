//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

// This file defines the dependency injection ProviderSet for the service layer and contains no business logic.
// The build tag `wireinject` excludes this source from normal `go build` and final binaries.
// Run `go generate ./...` or `go run github.com/google/wire/cmd/wire` to regenerate the Wire output (e.g. `wire_gen.go`), which will be included in final builds.
// Keep provider constructors here only; avoid init-time side effects or runtime logic in this file.

package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/service"
)

// ProviderSet is the Wire provider set for service layer
var ProviderSet = wire.NewSet(
	service.NewFolderService,
	service.NewSecretService,
	service.NewPermissionService,
	service.NewSystemService,
	service.NewBitwardenTransferService,
	ProvideResourceLookup,
	ProvidePermissionStore,
	ProvideAuthzEngine,
	ProvideAuthzChecker,
)

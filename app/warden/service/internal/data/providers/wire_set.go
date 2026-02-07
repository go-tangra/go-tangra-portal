//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

// This file defines the dependency injection ProviderSet for the data layer.

package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/internal/data"
)

// ProviderSet is the Wire provider set for data layer
var ProviderSet = wire.NewSet(
	data.NewRedisClient,
	data.NewEntClient,
	data.NewVaultClient,
	data.NewVaultKVStore,
	data.NewFolderRepo,
	data.NewSecretRepo,
	data.NewSecretVersionRepo,
	data.NewPermissionRepo,
	data.NewAuditLogRepo,
)

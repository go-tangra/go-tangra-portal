//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/service"
)

// ProviderSet is the Wire provider set for service layer
var ProviderSet = wire.NewSet(
	service.NewCategoryService,
	service.NewDocumentService,
	service.NewPermissionService,
)

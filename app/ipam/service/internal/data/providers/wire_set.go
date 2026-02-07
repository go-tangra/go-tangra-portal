//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

// This file defines the dependency injection ProviderSet for the data layer.

package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data"
)

var ProviderSet = wire.NewSet(
	data.NewRedisClient,
	data.NewEntClient,
	data.NewSubnetRepo,
	data.NewIpAddressRepo,
	data.NewVlanRepo,
	data.NewDeviceRepo,
	data.NewLocationRepo,
	data.NewIpScanJobRepo,
	data.NewDnsConfigRepo,
	data.NewIpGroupRepo,
	data.NewHostGroupRepo,
	data.NewAuditLogRepo,
)

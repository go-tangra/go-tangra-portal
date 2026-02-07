package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/service"
)

var ProviderSet = wire.NewSet(
	service.NewSystemService,
	service.NewSubnetService,
	service.NewVlanService,
	service.NewDeviceService,
	service.NewLocationService,
	service.NewIpAddressService,
	service.NewIpScanService,
	service.NewScanExecutor,
	service.NewIpGroupService,
	service.NewHostGroupService,
)

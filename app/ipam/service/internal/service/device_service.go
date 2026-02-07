package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
)

type DeviceService struct {
	ipamV1.UnimplementedDeviceServiceServer

	log        *log.Helper
	deviceRepo *data.DeviceRepo
}

func NewDeviceService(ctx *bootstrap.Context, deviceRepo *data.DeviceRepo) *DeviceService {
	return &DeviceService{
		log:        ctx.NewLoggerHelper("ipam/service/device"),
		deviceRepo: deviceRepo,
	}
}

func (s *DeviceService) CreateDevice(ctx context.Context, req *ipamV1.CreateDeviceRequest) (*ipamV1.CreateDeviceResponse, error) {
	opts := []func(*ent.DeviceCreate){}

	if req.DeviceType != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetDeviceType(int32(*req.DeviceType)) })
	}
	if req.Description != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetDescription(*req.Description) })
	}
	if req.Manufacturer != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetManufacturer(*req.Manufacturer) })
	}
	if req.Model != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetModel(*req.Model) })
	}
	if req.SerialNumber != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetSerialNumber(*req.SerialNumber) })
	}
	if req.AssetTag != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetAssetTag(*req.AssetTag) })
	}
	if req.LocationId != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetLocationID(*req.LocationId) })
	}
	if req.RackId != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetRackID(*req.RackId) })
	}
	if req.RackPosition != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetRackPosition(*req.RackPosition) })
	}
	if req.DeviceHeightU != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetDeviceHeightU(*req.DeviceHeightU) })
	}
	if req.PrimaryIp != nil {
		opts = append(opts, func(c *ent.DeviceCreate) { c.SetPrimaryIP(*req.PrimaryIp) })
	}

	entity, err := s.deviceRepo.Create(ctx, req.GetTenantId(), req.GetName(), opts...)
	if err != nil {
		return nil, err
	}

	return &ipamV1.CreateDeviceResponse{
		Device: deviceToProto(entity),
	}, nil
}

func (s *DeviceService) GetDevice(ctx context.Context, req *ipamV1.GetDeviceRequest) (*ipamV1.GetDeviceResponse, error) {
	entity, err := s.deviceRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, ipamV1.ErrorDeviceNotFound("device not found")
	}

	return &ipamV1.GetDeviceResponse{
		Device: deviceToProto(entity),
	}, nil
}

func (s *DeviceService) ListDevices(ctx context.Context, req *ipamV1.ListDevicesRequest) (*ipamV1.ListDevicesResponse, error) {
	filters := make(map[string]interface{})
	if req.DeviceType != nil {
		filters["device_type"] = int32(*req.DeviceType)
	}
	if req.Status != nil {
		filters["status"] = int32(*req.Status)
	}
	if req.LocationId != nil {
		filters["location_id"] = *req.LocationId
	}

	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())
	if req.GetNoPaging() {
		page = 0
		pageSize = 0
	}

	entities, total, err := s.deviceRepo.List(ctx, req.GetTenantId(), page, pageSize, filters)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.Device, len(entities))
	for i, e := range entities {
		items[i] = deviceToProto(e)
	}

	return &ipamV1.ListDevicesResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *DeviceService) UpdateDevice(ctx context.Context, req *ipamV1.UpdateDeviceRequest) (*ipamV1.UpdateDeviceResponse, error) {
	updates := make(map[string]interface{})

	if req.Data != nil {
		if req.Data.Name != nil {
			updates["name"] = *req.Data.Name
		}
		if req.Data.Description != nil {
			updates["description"] = *req.Data.Description
		}
		if req.Data.Status != nil {
			updates["status"] = int32(*req.Data.Status)
		}
		if req.Data.PrimaryIp != nil {
			updates["primary_ip"] = *req.Data.PrimaryIp
		}
	}

	entity, err := s.deviceRepo.Update(ctx, req.GetId(), updates)
	if err != nil {
		return nil, err
	}

	return &ipamV1.UpdateDeviceResponse{
		Device: deviceToProto(entity),
	}, nil
}

func (s *DeviceService) DeleteDevice(ctx context.Context, req *ipamV1.DeleteDeviceRequest) (*emptypb.Empty, error) {
	err := s.deviceRepo.Delete(ctx, req.GetId(), req.GetForce())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *DeviceService) GetDeviceAddresses(ctx context.Context, req *ipamV1.GetDeviceAddressesRequest) (*ipamV1.GetDeviceAddressesResponse, error) {
	// TODO: Implement GetDeviceAddresses - requires querying ip_addresses by device_id
	return &ipamV1.GetDeviceAddressesResponse{
		AddressIds: []string{},
	}, nil
}

func (s *DeviceService) GetDeviceInterfaces(ctx context.Context, req *ipamV1.GetDeviceInterfacesRequest) (*ipamV1.GetDeviceInterfacesResponse, error) {
	// TODO: Implement GetDeviceInterfaces - requires interface entity
	return &ipamV1.GetDeviceInterfacesResponse{
		Interfaces: []*ipamV1.DeviceInterface{},
	}, nil
}

func (s *DeviceService) CreateDeviceInterface(ctx context.Context, req *ipamV1.CreateDeviceInterfaceRequest) (*ipamV1.CreateDeviceInterfaceResponse, error) {
	// TODO: Implement CreateDeviceInterface - requires interface entity
	return nil, ipamV1.ErrorInternalServerError("not implemented")
}

func (s *DeviceService) DeleteDeviceInterface(ctx context.Context, req *ipamV1.DeleteDeviceInterfaceRequest) (*emptypb.Empty, error) {
	// TODO: Implement DeleteDeviceInterface - requires interface entity
	return nil, ipamV1.ErrorInternalServerError("not implemented")
}

// Helper function
func deviceToProto(e *ent.Device) *ipamV1.Device {
	if e == nil {
		return nil
	}

	status := ipamV1.DeviceStatus(e.Status)
	deviceType := ipamV1.DeviceType(e.DeviceType)

	result := &ipamV1.Device{
		Id:           &e.ID,
		TenantId:     e.TenantID,
		Name:         ptrString(e.Name),
		DeviceType:   &deviceType,
		Description:  ptrString(e.Description),
		Manufacturer: ptrString(e.Manufacturer),
		Model:        ptrString(e.Model),
		SerialNumber: ptrString(e.SerialNumber),
		AssetTag:     ptrString(e.AssetTag),
		LocationId:    ptrString(e.LocationID),
		RackId:        ptrString(e.RackID),
		RackPosition:  e.RackPosition,
		DeviceHeightU: e.DeviceHeightU,
		Status:        &status,
		PrimaryIp:     ptrString(e.PrimaryIP),
		Tags:         ptrString(e.Tags),
		Metadata:     ptrString(e.Metadata),
		CreatedBy:    e.CreateBy,
		UpdatedBy:    e.UpdateBy,
	}

	if e.CreateTime != nil {
		result.CreatedAt = timestamppb.New(*e.CreateTime)
	}
	if e.UpdateTime != nil {
		result.UpdatedAt = timestamppb.New(*e.UpdateTime)
	}

	return result
}

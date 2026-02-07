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

type IpAddressService struct {
	ipamV1.UnimplementedIpAddressServiceServer

	log           *log.Helper
	ipAddressRepo *data.IpAddressRepo
	subnetRepo    *data.SubnetRepo
}

func NewIpAddressService(ctx *bootstrap.Context, ipAddressRepo *data.IpAddressRepo, subnetRepo *data.SubnetRepo) *IpAddressService {
	return &IpAddressService{
		log:           ctx.NewLoggerHelper("ipam/service/ip_address"),
		ipAddressRepo: ipAddressRepo,
		subnetRepo:    subnetRepo,
	}
}

func (s *IpAddressService) CreateIpAddress(ctx context.Context, req *ipamV1.CreateIpAddressRequest) (*ipamV1.CreateIpAddressResponse, error) {
	opts := []func(*ent.IpAddressCreate){}

	if req.Hostname != nil {
		opts = append(opts, func(c *ent.IpAddressCreate) { c.SetHostname(*req.Hostname) })
	}
	if req.MacAddress != nil {
		opts = append(opts, func(c *ent.IpAddressCreate) { c.SetMACAddress(*req.MacAddress) })
	}
	if req.Description != nil {
		opts = append(opts, func(c *ent.IpAddressCreate) { c.SetDescription(*req.Description) })
	}
	if req.DeviceId != nil {
		opts = append(opts, func(c *ent.IpAddressCreate) { c.SetDeviceID(*req.DeviceId) })
	}
	if req.Status != nil {
		opts = append(opts, func(c *ent.IpAddressCreate) { c.SetStatus(int32(*req.Status)) })
	}
	if req.AddressType != nil {
		opts = append(opts, func(c *ent.IpAddressCreate) { c.SetAddressType(int32(*req.AddressType)) })
	}

	entity, err := s.ipAddressRepo.Create(ctx, req.GetTenantId(), req.GetAddress(), req.GetSubnetId(), opts...)
	if err != nil {
		return nil, err
	}

	return &ipamV1.CreateIpAddressResponse{
		IpAddress: ipAddressToProto(entity),
	}, nil
}

func (s *IpAddressService) GetIpAddress(ctx context.Context, req *ipamV1.GetIpAddressRequest) (*ipamV1.GetIpAddressResponse, error) {
	entity, err := s.ipAddressRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, ipamV1.ErrorAddressNotFound("ip address not found")
	}

	return &ipamV1.GetIpAddressResponse{
		IpAddress: ipAddressToProto(entity),
	}, nil
}

func (s *IpAddressService) ListIpAddresses(ctx context.Context, req *ipamV1.ListIpAddressesRequest) (*ipamV1.ListIpAddressesResponse, error) {
	filters := make(map[string]interface{})

	// If subnet ID is provided, fetch the subnet to get its CIDR for range-based matching
	// This allows finding IPs even if they have orphaned/mismatched subnet_ids
	if req.SubnetId != nil && *req.SubnetId != "" {
		subnet, err := s.subnetRepo.GetByID(ctx, *req.SubnetId)
		if err != nil {
			s.log.Warnf("Failed to get subnet %s for CIDR filtering: %v", *req.SubnetId, err)
			// Fall back to subnet_id based filtering
			filters["subnet_id"] = *req.SubnetId
		} else if subnet != nil {
			// Use CIDR-based filtering to include all IPs in the range
			filters["cidr"] = subnet.Cidr
		} else {
			// Subnet not found, fall back to subnet_id
			filters["subnet_id"] = *req.SubnetId
		}
	}

	if req.DeviceId != nil {
		filters["device_id"] = *req.DeviceId
	}
	if req.Status != nil {
		filters["status"] = int32(*req.Status)
	}

	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())
	if req.GetNoPaging() {
		page = 0
		pageSize = 0
	}

	entities, total, err := s.ipAddressRepo.List(ctx, req.GetTenantId(), page, pageSize, filters)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.IpAddress, len(entities))
	for i, e := range entities {
		items[i] = ipAddressToProto(e)
	}

	return &ipamV1.ListIpAddressesResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *IpAddressService) UpdateIpAddress(ctx context.Context, req *ipamV1.UpdateIpAddressRequest) (*ipamV1.UpdateIpAddressResponse, error) {
	updates := make(map[string]interface{})

	if req.Data != nil {
		if req.Data.Hostname != nil {
			updates["hostname"] = *req.Data.Hostname
		}
		if req.Data.MacAddress != nil {
			updates["mac_address"] = *req.Data.MacAddress
		}
		if req.Data.Description != nil {
			updates["description"] = *req.Data.Description
		}
		if req.Data.DeviceId != nil {
			updates["device_id"] = *req.Data.DeviceId
		}
		if req.Data.Status != nil {
			updates["status"] = int32(*req.Data.Status)
		}
	}

	entity, err := s.ipAddressRepo.Update(ctx, req.GetId(), updates)
	if err != nil {
		return nil, err
	}

	return &ipamV1.UpdateIpAddressResponse{
		IpAddress: ipAddressToProto(entity),
	}, nil
}

func (s *IpAddressService) DeleteIpAddress(ctx context.Context, req *ipamV1.DeleteIpAddressRequest) (*emptypb.Empty, error) {
	err := s.ipAddressRepo.Delete(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *IpAddressService) AllocateNextAddress(ctx context.Context, req *ipamV1.AllocateNextAddressRequest) (*ipamV1.AllocateNextAddressResponse, error) {
	// AllocateNext returns a string address - we need to create an entity
	_, err := s.ipAddressRepo.AllocateNext(ctx, req.GetTenantId(), req.GetSubnetId())
	if err != nil {
		return nil, err
	}

	// TODO: Once AllocateNext is fully implemented, return the created IpAddress
	return &ipamV1.AllocateNextAddressResponse{
		IpAddress: nil,
	}, nil
}

func (s *IpAddressService) BulkAllocateAddresses(ctx context.Context, req *ipamV1.BulkAllocateAddressesRequest) (*ipamV1.BulkAllocateAddressesResponse, error) {
	// TODO: Implement bulk allocation
	return nil, ipamV1.ErrorInternalServerError("bulk allocation not implemented")
}

func (s *IpAddressService) FindAddress(ctx context.Context, req *ipamV1.FindAddressRequest) (*ipamV1.FindAddressResponse, error) {
	entity, err := s.ipAddressRepo.GetByAddress(ctx, req.GetTenantId(), req.GetAddress())
	if err != nil {
		return nil, err
	}

	return &ipamV1.FindAddressResponse{
		IpAddress: ipAddressToProto(entity),
	}, nil
}

func (s *IpAddressService) PingAddress(ctx context.Context, req *ipamV1.PingAddressRequest) (*ipamV1.PingAddressResponse, error) {
	// TODO: Implement ping functionality
	return &ipamV1.PingAddressResponse{
		Reachable: false,
	}, nil
}

// Helper function
func ipAddressToProto(e *ent.IpAddress) *ipamV1.IpAddress {
	if e == nil {
		return nil
	}

	status := ipamV1.IpAddressStatus(e.Status)
	addressType := ipamV1.IpAddressType(e.AddressType)

	result := &ipamV1.IpAddress{
		Id:            &e.ID,
		TenantId:      e.TenantID,
		Address:       ptrString(e.Address),
		SubnetId:      ptrString(e.SubnetID),
		Hostname:      ptrString(e.Hostname),
		MacAddress:    ptrString(e.MACAddress),
		Description:   ptrString(e.Description),
		DeviceId:      ptrString(e.DeviceID),
		InterfaceName: ptrString(e.InterfaceName),
		Status:        &status,
		AddressType:   &addressType,
		IsPrimary:     ptrBool(e.IsPrimary),
		PtrRecord:     ptrString(e.PtrRecord),
		DnsName:       ptrString(e.DNSName),
		Owner:         ptrString(e.Owner),
		HasReverseDns: ptrBool(e.HasReverseDNS),
		Tags:          ptrString(e.Tags),
		Metadata:      ptrString(e.Metadata),
		Note:          ptrString(e.Note),
		CreatedBy:     e.CreateBy,
		UpdatedBy:     e.UpdateBy,
	}

	if e.CreateTime != nil {
		result.CreatedAt = timestamppb.New(*e.CreateTime)
	}
	if e.UpdateTime != nil {
		result.UpdatedAt = timestamppb.New(*e.UpdateTime)
	}
	if !e.LastSeen.IsZero() {
		result.LastSeen = timestamppb.New(e.LastSeen)
	}
	if e.LeaseExpiry != nil {
		result.LeaseExpiry = timestamppb.New(*e.LeaseExpiry)
	}

	return result
}

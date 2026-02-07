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

type VlanService struct {
	ipamV1.UnimplementedVlanServiceServer

	log      *log.Helper
	vlanRepo *data.VlanRepo
}

func NewVlanService(ctx *bootstrap.Context, vlanRepo *data.VlanRepo) *VlanService {
	return &VlanService{
		log:      ctx.NewLoggerHelper("ipam/service/vlan"),
		vlanRepo: vlanRepo,
	}
}

func (s *VlanService) CreateVlan(ctx context.Context, req *ipamV1.CreateVlanRequest) (*ipamV1.CreateVlanResponse, error) {
	opts := []func(*ent.VlanCreate){}

	if req.Description != nil {
		opts = append(opts, func(c *ent.VlanCreate) { c.SetDescription(*req.Description) })
	}
	if req.Domain != nil {
		opts = append(opts, func(c *ent.VlanCreate) { c.SetDomain(*req.Domain) })
	}
	if req.LocationId != nil {
		opts = append(opts, func(c *ent.VlanCreate) { c.SetLocationID(*req.LocationId) })
	}

	entity, err := s.vlanRepo.Create(ctx, req.GetTenantId(), req.GetVlanId(), req.GetName(), opts...)
	if err != nil {
		return nil, err
	}

	return &ipamV1.CreateVlanResponse{
		Vlan: vlanToProto(entity),
	}, nil
}

func (s *VlanService) GetVlan(ctx context.Context, req *ipamV1.GetVlanRequest) (*ipamV1.GetVlanResponse, error) {
	entity, err := s.vlanRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, ipamV1.ErrorVlanNotFound("vlan not found")
	}

	return &ipamV1.GetVlanResponse{
		Vlan: vlanToProto(entity),
	}, nil
}

func (s *VlanService) ListVlans(ctx context.Context, req *ipamV1.ListVlansRequest) (*ipamV1.ListVlansResponse, error) {
	filters := make(map[string]interface{})
	if req.LocationId != nil {
		filters["location_id"] = *req.LocationId
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

	entities, total, err := s.vlanRepo.List(ctx, req.GetTenantId(), page, pageSize, filters)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.Vlan, len(entities))
	for i, e := range entities {
		items[i] = vlanToProto(e)
	}

	return &ipamV1.ListVlansResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *VlanService) UpdateVlan(ctx context.Context, req *ipamV1.UpdateVlanRequest) (*ipamV1.UpdateVlanResponse, error) {
	updates := make(map[string]interface{})

	if req.Data != nil {
		if req.Data.Name != nil {
			updates["name"] = *req.Data.Name
		}
		if req.Data.Description != nil {
			updates["description"] = *req.Data.Description
		}
		if req.Data.Domain != nil {
			updates["domain"] = *req.Data.Domain
		}
		if req.Data.Status != nil {
			updates["status"] = int32(*req.Data.Status)
		}
	}

	entity, err := s.vlanRepo.Update(ctx, req.GetId(), updates)
	if err != nil {
		return nil, err
	}

	return &ipamV1.UpdateVlanResponse{
		Vlan: vlanToProto(entity),
	}, nil
}

func (s *VlanService) DeleteVlan(ctx context.Context, req *ipamV1.DeleteVlanRequest) (*emptypb.Empty, error) {
	err := s.vlanRepo.Delete(ctx, req.GetId(), req.GetForce())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *VlanService) GetVlanSubnets(ctx context.Context, req *ipamV1.GetVlanSubnetsRequest) (*ipamV1.GetVlanSubnetsResponse, error) {
	// TODO: Implement GetVlanSubnets - requires querying subnets by vlan_id
	return &ipamV1.GetVlanSubnetsResponse{
		SubnetIds: []string{},
	}, nil
}

// Helper function
func vlanToProto(e *ent.Vlan) *ipamV1.Vlan {
	if e == nil {
		return nil
	}

	status := ipamV1.VlanStatus(e.Status)

	result := &ipamV1.Vlan{
		Id:          &e.ID,
		TenantId:    e.TenantID,
		VlanId:      &e.VlanID,
		Name:        ptrString(e.Name),
		Description: ptrString(e.Description),
		Domain:      ptrString(e.Domain),
		LocationId:  ptrString(e.LocationID),
		Status:      &status,
		Tags:        ptrString(e.Tags),
		Metadata:    ptrString(e.Metadata),
		CreatedBy:   e.CreateBy,
		UpdatedBy:   e.UpdateBy,
	}

	if e.CreateTime != nil {
		result.CreatedAt = timestamppb.New(*e.CreateTime)
	}
	if e.UpdateTime != nil {
		result.UpdatedAt = timestamppb.New(*e.UpdateTime)
	}

	return result
}

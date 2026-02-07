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

type HostGroupService struct {
	ipamV1.UnimplementedHostGroupServiceServer

	log           *log.Helper
	hostGroupRepo *data.HostGroupRepo
}

func NewHostGroupService(ctx *bootstrap.Context, hostGroupRepo *data.HostGroupRepo) *HostGroupService {
	return &HostGroupService{
		log:           ctx.NewLoggerHelper("ipam/service/host-group"),
		hostGroupRepo: hostGroupRepo,
	}
}

func (s *HostGroupService) CreateHostGroup(ctx context.Context, req *ipamV1.CreateHostGroupRequest) (*ipamV1.CreateHostGroupResponse, error) {
	// Build options from request
	opts := []func(*ent.HostGroupCreate){}

	if req.Description != nil {
		opts = append(opts, func(c *ent.HostGroupCreate) { c.SetDescription(*req.Description) })
	}
	if req.Status != nil {
		opts = append(opts, func(c *ent.HostGroupCreate) { c.SetStatus(int32(*req.Status)) })
	}
	if req.Tags != nil {
		opts = append(opts, func(c *ent.HostGroupCreate) { c.SetTags(*req.Tags) })
	}
	if req.Metadata != nil {
		opts = append(opts, func(c *ent.HostGroupCreate) { c.SetMetadata(*req.Metadata) })
	}

	entity, err := s.hostGroupRepo.Create(ctx, req.GetTenantId(), req.GetName(), opts...)
	if err != nil {
		return nil, err
	}

	// Add initial device members if provided
	if len(req.DeviceIds) > 0 {
		for i, deviceID := range req.DeviceIds {
			_, err := s.hostGroupRepo.AddMember(ctx, entity.ID, deviceID, int32(i))
			if err != nil {
				s.log.Warnf("Failed to add initial device member to host group: %v", err)
			}
		}
	}

	// Get member count
	memberCount, _ := s.hostGroupRepo.GetMemberCount(ctx, entity.ID)

	return &ipamV1.CreateHostGroupResponse{
		HostGroup: hostGroupToProto(entity, int32(memberCount)),
	}, nil
}

func (s *HostGroupService) GetHostGroup(ctx context.Context, req *ipamV1.GetHostGroupRequest) (*ipamV1.GetHostGroupResponse, error) {
	entity, err := s.hostGroupRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, ipamV1.ErrorHostGroupNotFound("Host group not found")
	}

	memberCount, _ := s.hostGroupRepo.GetMemberCount(ctx, entity.ID)

	response := &ipamV1.GetHostGroupResponse{
		HostGroup: hostGroupToProto(entity, int32(memberCount)),
	}

	// Include members if requested
	if req.GetIncludeMembers() {
		members, _, err := s.hostGroupRepo.ListMembers(ctx, entity.ID, 0, 0)
		if err == nil {
			response.Members = make([]*ipamV1.HostGroupMember, len(members))
			for i, m := range members {
				response.Members[i] = hostGroupMemberToProto(m)
			}
		}
	}

	return response, nil
}

func (s *HostGroupService) ListHostGroups(ctx context.Context, req *ipamV1.ListHostGroupsRequest) (*ipamV1.ListHostGroupsResponse, error) {
	filters := make(map[string]interface{})
	if req.Status != nil {
		filters["status"] = int32(*req.Status)
	}
	if req.Query != nil {
		filters["query"] = *req.Query
	}

	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())
	if req.GetNoPaging() {
		page = 0
		pageSize = 0
	}

	entities, total, err := s.hostGroupRepo.List(ctx, req.GetTenantId(), page, pageSize, filters)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.HostGroup, len(entities))
	for i, e := range entities {
		memberCount, _ := s.hostGroupRepo.GetMemberCount(ctx, e.ID)
		items[i] = hostGroupToProto(e, int32(memberCount))
	}

	return &ipamV1.ListHostGroupsResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *HostGroupService) UpdateHostGroup(ctx context.Context, req *ipamV1.UpdateHostGroupRequest) (*ipamV1.UpdateHostGroupResponse, error) {
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
		if req.Data.Tags != nil {
			updates["tags"] = *req.Data.Tags
		}
		if req.Data.Metadata != nil {
			updates["metadata"] = *req.Data.Metadata
		}
	}

	entity, err := s.hostGroupRepo.Update(ctx, req.GetId(), updates)
	if err != nil {
		return nil, err
	}

	memberCount, _ := s.hostGroupRepo.GetMemberCount(ctx, entity.ID)

	return &ipamV1.UpdateHostGroupResponse{
		HostGroup: hostGroupToProto(entity, int32(memberCount)),
	}, nil
}

func (s *HostGroupService) DeleteHostGroup(ctx context.Context, req *ipamV1.DeleteHostGroupRequest) (*emptypb.Empty, error) {
	err := s.hostGroupRepo.Delete(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *HostGroupService) AddHostGroupMember(ctx context.Context, req *ipamV1.AddHostGroupMemberRequest) (*ipamV1.AddHostGroupMemberResponse, error) {
	// Verify group exists
	group, err := s.hostGroupRepo.GetByID(ctx, req.GetHostGroupId())
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, ipamV1.ErrorHostGroupNotFound("Host group not found")
	}

	member, err := s.hostGroupRepo.AddMember(ctx, req.GetHostGroupId(), req.GetDeviceId(), req.GetSequence())
	if err != nil {
		return nil, err
	}

	// Fetch member with device details
	memberWithDevice, err := s.hostGroupRepo.GetMemberByDeviceID(ctx, req.GetHostGroupId(), req.GetDeviceId())
	if err != nil || memberWithDevice == nil {
		// Return basic member if we can't fetch with device details
		return &ipamV1.AddHostGroupMemberResponse{
			Member: hostGroupMemberToProto(member),
		}, nil
	}

	return &ipamV1.AddHostGroupMemberResponse{
		Member: hostGroupMemberToProto(memberWithDevice),
	}, nil
}

func (s *HostGroupService) RemoveHostGroupMember(ctx context.Context, req *ipamV1.RemoveHostGroupMemberRequest) (*emptypb.Empty, error) {
	err := s.hostGroupRepo.RemoveMember(ctx, req.GetHostGroupId(), req.GetMemberId())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *HostGroupService) ListHostGroupMembers(ctx context.Context, req *ipamV1.ListHostGroupMembersRequest) (*ipamV1.ListHostGroupMembersResponse, error) {
	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())
	if req.GetNoPaging() {
		page = 0
		pageSize = 0
	}

	members, total, err := s.hostGroupRepo.ListMembers(ctx, req.GetHostGroupId(), page, pageSize)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.HostGroupMember, len(members))
	for i, m := range members {
		items[i] = hostGroupMemberToProto(m)
	}

	return &ipamV1.ListHostGroupMembersResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *HostGroupService) UpdateHostGroupMember(ctx context.Context, req *ipamV1.UpdateHostGroupMemberRequest) (*ipamV1.UpdateHostGroupMemberResponse, error) {
	member, err := s.hostGroupRepo.UpdateMember(ctx, req.GetHostGroupId(), req.GetMemberId(), req.Sequence)
	if err != nil {
		return nil, err
	}

	return &ipamV1.UpdateHostGroupMemberResponse{
		Member: hostGroupMemberToProto(member),
	}, nil
}

func (s *HostGroupService) ListDeviceHostGroups(ctx context.Context, req *ipamV1.ListDeviceHostGroupsRequest) (*ipamV1.ListDeviceHostGroupsResponse, error) {
	groups, err := s.hostGroupRepo.ListGroupsForDevice(ctx, req.GetTenantId(), req.GetDeviceId())
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.HostGroup, len(groups))
	for i, g := range groups {
		memberCount, _ := s.hostGroupRepo.GetMemberCount(ctx, g.ID)
		items[i] = hostGroupToProto(g, int32(memberCount))
	}

	return &ipamV1.ListDeviceHostGroupsResponse{
		Groups: items,
	}, nil
}

// Helper functions

func hostGroupToProto(e *ent.HostGroup, memberCount int32) *ipamV1.HostGroup {
	if e == nil {
		return nil
	}

	status := ipamV1.HostGroupStatus(e.Status)

	result := &ipamV1.HostGroup{
		Id:          &e.ID,
		TenantId:    e.TenantID,
		Name:        &e.Name,
		Description: ptrString(e.Description),
		Status:      &status,
		MemberCount: &memberCount,
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

func hostGroupMemberToProto(e *ent.HostGroupMember) *ipamV1.HostGroupMember {
	if e == nil {
		return nil
	}

	result := &ipamV1.HostGroupMember{
		Id:          &e.ID,
		HostGroupId: &e.HostGroupID,
		DeviceId:    &e.DeviceID,
		Sequence:    &e.Sequence,
	}

	// Add device details if available (via edge loading)
	if e.Edges.Device != nil {
		d := e.Edges.Device
		result.DeviceName = &d.Name
		result.DeviceType = &d.DeviceType
		result.DeviceStatus = &d.Status
		if d.PrimaryIP != "" {
			result.DevicePrimaryIp = &d.PrimaryIP
		}
	}

	if e.CreateTime != nil {
		result.CreatedAt = timestamppb.New(*e.CreateTime)
	}
	if e.UpdateTime != nil {
		result.UpdatedAt = timestamppb.New(*e.UpdateTime)
	}

	return result
}

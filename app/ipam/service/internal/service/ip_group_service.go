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

type IpGroupService struct {
	ipamV1.UnimplementedIpGroupServiceServer

	log         *log.Helper
	ipGroupRepo *data.IpGroupRepo
}

func NewIpGroupService(ctx *bootstrap.Context, ipGroupRepo *data.IpGroupRepo) *IpGroupService {
	return &IpGroupService{
		log:         ctx.NewLoggerHelper("ipam/service/ip-group"),
		ipGroupRepo: ipGroupRepo,
	}
}

func (s *IpGroupService) CreateIpGroup(ctx context.Context, req *ipamV1.CreateIpGroupRequest) (*ipamV1.CreateIpGroupResponse, error) {
	// Build options from request
	opts := []func(*ent.IpGroupCreate){}

	if req.Description != nil {
		opts = append(opts, func(c *ent.IpGroupCreate) { c.SetDescription(*req.Description) })
	}
	if req.Status != nil {
		opts = append(opts, func(c *ent.IpGroupCreate) { c.SetStatus(int32(*req.Status)) })
	}
	if req.Tags != nil {
		opts = append(opts, func(c *ent.IpGroupCreate) { c.SetTags(*req.Tags) })
	}
	if req.Metadata != nil {
		opts = append(opts, func(c *ent.IpGroupCreate) { c.SetMetadata(*req.Metadata) })
	}

	entity, err := s.ipGroupRepo.Create(ctx, req.GetTenantId(), req.GetName(), opts...)
	if err != nil {
		return nil, err
	}

	// Add initial members if provided
	if len(req.Members) > 0 {
		for i, member := range req.Members {
			seq := member.Sequence
			if seq == nil {
				seqVal := int32(i)
				seq = &seqVal
			}
			desc := ""
			if member.Description != nil {
				desc = *member.Description
			}
			_, err := s.ipGroupRepo.AddMember(ctx, entity.ID, int32(member.GetMemberType()), member.GetValue(), desc, *seq)
			if err != nil {
				s.log.Warnf("Failed to add initial member to IP group: %v", err)
			}
		}
	}

	// Get member count
	memberCount, _ := s.ipGroupRepo.GetMemberCount(ctx, entity.ID)

	return &ipamV1.CreateIpGroupResponse{
		IpGroup: ipGroupToProto(entity, int32(memberCount)),
	}, nil
}

func (s *IpGroupService) GetIpGroup(ctx context.Context, req *ipamV1.GetIpGroupRequest) (*ipamV1.GetIpGroupResponse, error) {
	entity, err := s.ipGroupRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, ipamV1.ErrorIpGroupNotFound("IP group not found")
	}

	memberCount, _ := s.ipGroupRepo.GetMemberCount(ctx, entity.ID)

	response := &ipamV1.GetIpGroupResponse{
		IpGroup: ipGroupToProto(entity, int32(memberCount)),
	}

	// Include members if requested
	if req.GetIncludeMembers() {
		members, _, err := s.ipGroupRepo.ListMembers(ctx, entity.ID, 0, 0)
		if err == nil {
			response.Members = make([]*ipamV1.IpGroupMember, len(members))
			for i, m := range members {
				response.Members[i] = ipGroupMemberToProto(m)
			}
		}
	}

	return response, nil
}

func (s *IpGroupService) ListIpGroups(ctx context.Context, req *ipamV1.ListIpGroupsRequest) (*ipamV1.ListIpGroupsResponse, error) {
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

	entities, total, err := s.ipGroupRepo.List(ctx, req.GetTenantId(), page, pageSize, filters)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.IpGroup, len(entities))
	for i, e := range entities {
		memberCount, _ := s.ipGroupRepo.GetMemberCount(ctx, e.ID)
		items[i] = ipGroupToProto(e, int32(memberCount))
	}

	return &ipamV1.ListIpGroupsResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *IpGroupService) UpdateIpGroup(ctx context.Context, req *ipamV1.UpdateIpGroupRequest) (*ipamV1.UpdateIpGroupResponse, error) {
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

	entity, err := s.ipGroupRepo.Update(ctx, req.GetId(), updates)
	if err != nil {
		return nil, err
	}

	memberCount, _ := s.ipGroupRepo.GetMemberCount(ctx, entity.ID)

	return &ipamV1.UpdateIpGroupResponse{
		IpGroup: ipGroupToProto(entity, int32(memberCount)),
	}, nil
}

func (s *IpGroupService) DeleteIpGroup(ctx context.Context, req *ipamV1.DeleteIpGroupRequest) (*emptypb.Empty, error) {
	err := s.ipGroupRepo.Delete(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *IpGroupService) AddIpGroupMember(ctx context.Context, req *ipamV1.AddIpGroupMemberRequest) (*ipamV1.AddIpGroupMemberResponse, error) {
	// Verify group exists
	group, err := s.ipGroupRepo.GetByID(ctx, req.GetIpGroupId())
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, ipamV1.ErrorIpGroupNotFound("IP group not found")
	}

	desc := ""
	if req.Description != nil {
		desc = *req.Description
	}

	member, err := s.ipGroupRepo.AddMember(ctx, req.GetIpGroupId(), int32(req.GetMemberType()), req.GetValue(), desc, req.GetSequence())
	if err != nil {
		return nil, err
	}

	return &ipamV1.AddIpGroupMemberResponse{
		Member: ipGroupMemberToProto(member),
	}, nil
}

func (s *IpGroupService) RemoveIpGroupMember(ctx context.Context, req *ipamV1.RemoveIpGroupMemberRequest) (*emptypb.Empty, error) {
	err := s.ipGroupRepo.RemoveMember(ctx, req.GetIpGroupId(), req.GetMemberId())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *IpGroupService) ListIpGroupMembers(ctx context.Context, req *ipamV1.ListIpGroupMembersRequest) (*ipamV1.ListIpGroupMembersResponse, error) {
	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())
	if req.GetNoPaging() {
		page = 0
		pageSize = 0
	}

	members, total, err := s.ipGroupRepo.ListMembers(ctx, req.GetIpGroupId(), page, pageSize)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.IpGroupMember, len(members))
	for i, m := range members {
		items[i] = ipGroupMemberToProto(m)
	}

	return &ipamV1.ListIpGroupMembersResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *IpGroupService) UpdateIpGroupMember(ctx context.Context, req *ipamV1.UpdateIpGroupMemberRequest) (*ipamV1.UpdateIpGroupMemberResponse, error) {
	member, err := s.ipGroupRepo.UpdateMember(ctx, req.GetIpGroupId(), req.GetMemberId(), req.Description, req.Sequence)
	if err != nil {
		return nil, err
	}

	return &ipamV1.UpdateIpGroupMemberResponse{
		Member: ipGroupMemberToProto(member),
	}, nil
}

func (s *IpGroupService) CheckIpInGroup(ctx context.Context, req *ipamV1.CheckIpInGroupRequest) (*ipamV1.CheckIpInGroupResponse, error) {
	groups, err := s.ipGroupRepo.CheckIpInGroups(ctx, req.GetTenantId(), req.GetIpAddress(), req.GetGroupIds())
	if err != nil {
		return nil, err
	}

	matchingGroups := make([]*ipamV1.IpGroup, len(groups))
	for i, g := range groups {
		memberCount, _ := s.ipGroupRepo.GetMemberCount(ctx, g.ID)
		matchingGroups[i] = ipGroupToProto(g, int32(memberCount))
	}

	return &ipamV1.CheckIpInGroupResponse{
		MatchingGroups: matchingGroups,
	}, nil
}

// Helper functions

func ipGroupToProto(e *ent.IpGroup, memberCount int32) *ipamV1.IpGroup {
	if e == nil {
		return nil
	}

	status := ipamV1.IpGroupStatus(e.Status)

	result := &ipamV1.IpGroup{
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

func ipGroupMemberToProto(e *ent.IpGroupMember) *ipamV1.IpGroupMember {
	if e == nil {
		return nil
	}

	memberType := ipamV1.IpGroupMemberType(e.MemberType)

	result := &ipamV1.IpGroupMember{
		Id:          &e.ID,
		IpGroupId:   &e.IPGroupID,
		MemberType:  &memberType,
		Value:       &e.Value,
		Description: ptrString(e.Description),
		Sequence:    &e.Sequence,
	}

	if e.CreateTime != nil {
		result.CreatedAt = timestamppb.New(*e.CreateTime)
	}
	if e.UpdateTime != nil {
		result.UpdatedAt = timestamppb.New(*e.UpdateTime)
	}

	return result
}

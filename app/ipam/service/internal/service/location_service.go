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

type LocationService struct {
	ipamV1.UnimplementedLocationServiceServer

	log          *log.Helper
	locationRepo *data.LocationRepo
}

func NewLocationService(ctx *bootstrap.Context, locationRepo *data.LocationRepo) *LocationService {
	return &LocationService{
		log:          ctx.NewLoggerHelper("ipam/service/location"),
		locationRepo: locationRepo,
	}
}

func (s *LocationService) CreateLocation(ctx context.Context, req *ipamV1.CreateLocationRequest) (*ipamV1.CreateLocationResponse, error) {
	opts := []func(*ent.LocationCreate){}

	if req.Code != nil {
		opts = append(opts, func(c *ent.LocationCreate) { c.SetCode(*req.Code) })
	}
	if req.LocationType != nil {
		opts = append(opts, func(c *ent.LocationCreate) { c.SetLocationType(int32(*req.LocationType)) })
	}
	if req.Description != nil {
		opts = append(opts, func(c *ent.LocationCreate) { c.SetDescription(*req.Description) })
	}
	if req.ParentId != nil {
		opts = append(opts, func(c *ent.LocationCreate) { c.SetParentID(*req.ParentId) })
	}
	if req.Address != nil {
		opts = append(opts, func(c *ent.LocationCreate) { c.SetAddress(*req.Address) })
	}
	if req.City != nil {
		opts = append(opts, func(c *ent.LocationCreate) { c.SetCity(*req.City) })
	}
	if req.Country != nil {
		opts = append(opts, func(c *ent.LocationCreate) { c.SetCountry(*req.Country) })
	}
	if req.RackSizeU != nil {
		opts = append(opts, func(c *ent.LocationCreate) { c.SetRackSizeU(*req.RackSizeU) })
	}

	entity, err := s.locationRepo.Create(ctx, req.GetTenantId(), req.GetName(), opts...)
	if err != nil {
		return nil, err
	}

	return &ipamV1.CreateLocationResponse{
		Location: locationToProto(entity),
	}, nil
}

func (s *LocationService) GetLocation(ctx context.Context, req *ipamV1.GetLocationRequest) (*ipamV1.GetLocationResponse, error) {
	entity, err := s.locationRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, ipamV1.ErrorLocationNotFound("location not found")
	}

	return &ipamV1.GetLocationResponse{
		Location: locationToProto(entity),
	}, nil
}

func (s *LocationService) ListLocations(ctx context.Context, req *ipamV1.ListLocationsRequest) (*ipamV1.ListLocationsResponse, error) {
	filters := make(map[string]interface{})
	if req.ParentId != nil {
		filters["parent_id"] = *req.ParentId
	}
	if req.LocationType != nil {
		filters["location_type"] = int32(*req.LocationType)
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

	entities, total, err := s.locationRepo.List(ctx, req.GetTenantId(), page, pageSize, filters)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.Location, len(entities))
	for i, e := range entities {
		items[i] = locationToProto(e)
	}

	return &ipamV1.ListLocationsResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *LocationService) UpdateLocation(ctx context.Context, req *ipamV1.UpdateLocationRequest) (*ipamV1.UpdateLocationResponse, error) {
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
	}

	entity, err := s.locationRepo.Update(ctx, req.GetId(), updates)
	if err != nil {
		return nil, err
	}

	return &ipamV1.UpdateLocationResponse{
		Location: locationToProto(entity),
	}, nil
}

func (s *LocationService) DeleteLocation(ctx context.Context, req *ipamV1.DeleteLocationRequest) (*emptypb.Empty, error) {
	err := s.locationRepo.Delete(ctx, req.GetId(), req.GetForce())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *LocationService) GetLocationTree(ctx context.Context, req *ipamV1.GetLocationTreeRequest) (*ipamV1.GetLocationTreeResponse, error) {
	entities, err := s.locationRepo.GetTree(ctx, req.GetTenantId(), req.GetRootId())
	if err != nil {
		return nil, err
	}

	// Build a map of location ID to tree node
	nodeMap := make(map[string]*ipamV1.LocationTreeNode)
	for _, e := range entities {
		nodeMap[e.ID] = &ipamV1.LocationTreeNode{
			Location: locationToProto(e),
			Children: []*ipamV1.LocationTreeNode{},
		}
	}

	// Build tree structure by linking children to parents
	var roots []*ipamV1.LocationTreeNode
	for _, e := range entities {
		node := nodeMap[e.ID]
		if e.ParentID == "" {
			// Root node
			roots = append(roots, node)
		} else {
			// Child node - attach to parent
			if parent, ok := nodeMap[e.ParentID]; ok {
				parent.Children = append(parent.Children, node)
			} else {
				// Parent not found (might be outside the subtree), treat as root
				roots = append(roots, node)
			}
		}
	}

	return &ipamV1.GetLocationTreeResponse{
		Nodes: roots,
	}, nil
}

// Helper function
func locationToProto(e *ent.Location) *ipamV1.Location {
	if e == nil {
		return nil
	}

	status := ipamV1.LocationStatus(e.Status)
	locationType := ipamV1.LocationType(e.LocationType)

	result := &ipamV1.Location{
		Id:           &e.ID,
		TenantId:     e.TenantID,
		Name:         ptrString(e.Name),
		Code:         ptrString(e.Code),
		LocationType: &locationType,
		Description:  ptrString(e.Description),
		ParentId:     ptrString(e.ParentID),
		Path:         ptrString(e.Path),
		Address:      ptrString(e.Address),
		City:         ptrString(e.City),
		Country:      ptrString(e.Country),
		Status:       &status,
		Tags:         ptrString(e.Tags),
		Metadata:     ptrString(e.Metadata),
		RackSizeU:    e.RackSizeU,
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

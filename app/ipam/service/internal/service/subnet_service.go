package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/biz"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/ipscanjob"
)

type SubnetService struct {
	ipamV1.UnimplementedSubnetServiceServer

	log         *log.Helper
	subnetRepo  *data.SubnetRepo
	scanJobRepo *data.IpScanJobRepo
}

func NewSubnetService(ctx *bootstrap.Context, subnetRepo *data.SubnetRepo, scanJobRepo *data.IpScanJobRepo) *SubnetService {
	return &SubnetService{
		log:         ctx.NewLoggerHelper("ipam/service/subnet"),
		subnetRepo:  subnetRepo,
		scanJobRepo: scanJobRepo,
	}
}

func (s *SubnetService) CreateSubnet(ctx context.Context, req *ipamV1.CreateSubnetRequest) (*ipamV1.CreateSubnetResponse, error) {
	// Build options from request
	opts := []func(*ent.SubnetCreate){}

	if req.Description != nil {
		opts = append(opts, func(c *ent.SubnetCreate) { c.SetDescription(*req.Description) })
	}
	if req.Gateway != nil {
		opts = append(opts, func(c *ent.SubnetCreate) { c.SetGateway(*req.Gateway) })
	}
	if req.DnsServers != nil {
		opts = append(opts, func(c *ent.SubnetCreate) { c.SetDNSServers(*req.DnsServers) })
	}
	if req.VlanId != nil {
		opts = append(opts, func(c *ent.SubnetCreate) { c.SetVlanID(*req.VlanId) })
	}
	if req.ParentId != nil {
		opts = append(opts, func(c *ent.SubnetCreate) { c.SetParentID(*req.ParentId) })
	}
	if req.LocationId != nil {
		opts = append(opts, func(c *ent.SubnetCreate) { c.SetLocationID(*req.LocationId) })
	}

	entity, err := s.subnetRepo.Create(ctx, req.GetTenantId(), req.GetName(), req.GetCidr(), opts...)
	if err != nil {
		return nil, err
	}

	// If this is a child subnet, reassign IP addresses from parent that fall within this subnet's range
	if req.ParentId != nil && *req.ParentId != "" {
		reassigned, err := s.subnetRepo.ReassignIPsFromParentToChild(ctx, *req.ParentId, entity.ID, entity.Cidr)
		if err != nil {
			// Log the error but don't fail the create - the subnet was already created
			s.log.Warnf("Failed to reassign IPs from parent to child subnet %s: %v", entity.ID, err)
		} else if reassigned > 0 {
			s.log.Infof("Reassigned %d IP addresses to new child subnet %s", reassigned, entity.ID)
		}
	}

	// Trigger auto-scan if requested
	if req.AutoScan != nil && *req.AutoScan {
		if err := s.triggerAutoScan(ctx, req.GetTenantId(), entity.ID, entity.Cidr, req.ScanConfig); err != nil {
			// Log the error but don't fail the create
			s.log.Warnf("Failed to trigger auto-scan for subnet %s: %v", entity.ID, err)
		}
	}

	return &ipamV1.CreateSubnetResponse{
		Subnet: subnetToProto(entity),
	}, nil
}

// triggerAutoScan creates a scan job for the newly created subnet
func (s *SubnetService) triggerAutoScan(ctx context.Context, tenantID uint32, subnetID, cidr string, scanConfig *ipamV1.ScanConfig) error {
	// Validate CIDR for scanning
	if err := biz.ValidateCIDRForScanning(cidr); err != nil {
		s.log.Infof("Subnet %s not suitable for auto-scan: %v", subnetID, err)
		return nil // Not an error, just skip
	}

	// Calculate total addresses
	totalAddresses, err := biz.GetHostAddressCount(cidr)
	if err != nil {
		return err
	}

	// Build scan config
	var config *data.ScanConfig
	if scanConfig != nil {
		config = &data.ScanConfig{}
		if scanConfig.TimeoutMs != nil {
			config.TimeoutMs = *scanConfig.TimeoutMs
		}
		if scanConfig.Concurrency != nil {
			config.Concurrency = *scanConfig.Concurrency
		}
		if scanConfig.SkipReverseDns != nil {
			config.SkipReverseDNS = *scanConfig.SkipReverseDns
		}
		if scanConfig.TcpProbePorts != nil {
			config.TCPProbePorts = *scanConfig.TcpProbePorts
		}
	}

	// Create the scan job
	_, err = s.scanJobRepo.Create(ctx, tenantID, subnetID, ipscanjob.TriggeredByAUTO, totalAddresses, config)
	if err != nil {
		return err
	}

	s.log.Infof("Auto-scan job created for subnet %s", subnetID)
	return nil
}

func (s *SubnetService) GetSubnet(ctx context.Context, req *ipamV1.GetSubnetRequest) (*ipamV1.GetSubnetResponse, error) {
	entity, err := s.subnetRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, ipamV1.ErrorSubnetNotFound("subnet not found")
	}

	return &ipamV1.GetSubnetResponse{
		Subnet: subnetToProto(entity),
	}, nil
}

func (s *SubnetService) ListSubnets(ctx context.Context, req *ipamV1.ListSubnetsRequest) (*ipamV1.ListSubnetsResponse, error) {
	filters := make(map[string]interface{})
	if req.VlanId != nil {
		filters["vlan_id"] = *req.VlanId
	}
	if req.ParentId != nil {
		filters["parent_id"] = *req.ParentId
	}
	if req.LocationId != nil {
		filters["location_id"] = *req.LocationId
	}
	if req.Status != nil {
		filters["status"] = int32(*req.Status)
	}
	if req.IpVersion != nil {
		filters["ip_version"] = *req.IpVersion
	}

	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())
	if req.GetNoPaging() {
		page = 0
		pageSize = 0
	}

	entities, total, err := s.subnetRepo.List(ctx, req.GetTenantId(), page, pageSize, filters)
	if err != nil {
		return nil, err
	}

	items := make([]*ipamV1.Subnet, len(entities))
	for i, e := range entities {
		items[i] = subnetToProto(e)
	}

	return &ipamV1.ListSubnetsResponse{
		Items: items,
		Total: ptrInt32(int32(total)),
	}, nil
}

func (s *SubnetService) UpdateSubnet(ctx context.Context, req *ipamV1.UpdateSubnetRequest) (*ipamV1.UpdateSubnetResponse, error) {
	updates := make(map[string]interface{})

	if req.Data != nil {
		if req.Data.Name != nil {
			updates["name"] = *req.Data.Name
		}
		if req.Data.Description != nil {
			updates["description"] = *req.Data.Description
		}
		if req.Data.Gateway != nil {
			updates["gateway"] = *req.Data.Gateway
		}
		if req.Data.DnsServers != nil {
			updates["dns_servers"] = *req.Data.DnsServers
		}
		if req.Data.VlanId != nil {
			updates["vlan_id"] = *req.Data.VlanId
		}
		if req.Data.LocationId != nil {
			updates["location_id"] = *req.Data.LocationId
		}
		if req.Data.Status != nil {
			updates["status"] = int32(*req.Data.Status)
		}
	}

	entity, err := s.subnetRepo.Update(ctx, req.GetId(), updates)
	if err != nil {
		return nil, err
	}

	return &ipamV1.UpdateSubnetResponse{
		Subnet: subnetToProto(entity),
	}, nil
}

func (s *SubnetService) DeleteSubnet(ctx context.Context, req *ipamV1.DeleteSubnetRequest) (*emptypb.Empty, error) {
	err := s.subnetRepo.Delete(ctx, req.GetId(), req.GetForce())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *SubnetService) GetSubnetTree(ctx context.Context, req *ipamV1.GetSubnetTreeRequest) (*ipamV1.GetSubnetTreeResponse, error) {
	entities, err := s.subnetRepo.GetTree(ctx, req.GetTenantId(), req.GetRootId(), int(req.GetMaxDepth()))
	if err != nil {
		return nil, err
	}

	// Build a map of subnet ID to tree node
	nodeMap := make(map[string]*ipamV1.SubnetTreeNode)
	for _, e := range entities {
		nodeMap[e.ID] = &ipamV1.SubnetTreeNode{
			Subnet:   subnetToProto(e),
			Children: []*ipamV1.SubnetTreeNode{},
		}
	}

	// Build tree structure by linking children to parents
	var roots []*ipamV1.SubnetTreeNode
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
				// Parent not found, treat as root
				roots = append(roots, node)
			}
		}
	}

	return &ipamV1.GetSubnetTreeResponse{
		Nodes: roots,
	}, nil
}

func (s *SubnetService) GetSubnetStats(ctx context.Context, req *ipamV1.GetSubnetStatsRequest) (*ipamV1.GetSubnetStatsResponse, error) {
	total, used, available, err := s.subnetRepo.GetStats(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	var utilization float64
	if total > 0 {
		utilization = float64(used) / float64(total) * 100
	}

	return &ipamV1.GetSubnetStatsResponse{
		TotalAddresses:     total,
		UsedAddresses:      used,
		AvailableAddresses: available,
		Utilization:        utilization,
	}, nil
}

func (s *SubnetService) ScanSubnet(ctx context.Context, req *ipamV1.ScanSubnetRequest) (*ipamV1.ScanSubnetResponse, error) {
	// TODO: Implement network scanning
	return &ipamV1.ScanSubnetResponse{
		DiscoveredAddresses: []string{},
		NewAddresses:        0,
	}, nil
}

// Helper functions

func subnetToProto(e *ent.Subnet) *ipamV1.Subnet {
	if e == nil {
		return nil
	}

	status := ipamV1.SubnetStatus(e.Status)

	result := &ipamV1.Subnet{
		Id:               &e.ID,
		TenantId:         e.TenantID,
		Name:             &e.Name,
		Cidr:             &e.Cidr,
		Description:      ptrString(e.Description),
		Gateway:          ptrString(e.Gateway),
		DnsServers:       ptrString(e.DNSServers),
		VlanId:           ptrString(e.VlanID),
		ParentId:         ptrString(e.ParentID),
		LocationId:       ptrString(e.LocationID),
		Status:           &status,
		IpVersion:        &e.IPVersion,
		NetworkAddress:   ptrString(e.NetworkAddress),
		BroadcastAddress: ptrString(e.BroadcastAddress),
		Mask:             ptrString(e.Mask),
		PrefixLength:     &e.PrefixLength,
		TotalAddresses:   &e.TotalAddresses,
		Tags:             ptrString(e.Tags),
		Metadata:         ptrString(e.Metadata),
		CreatedBy:        e.CreateBy,
		UpdatedBy:        e.UpdateBy,
	}

	if e.CreateTime != nil {
		result.CreatedAt = timestamppb.New(*e.CreateTime)
	}
	if e.UpdateTime != nil {
		result.UpdatedAt = timestamppb.New(*e.UpdateTime)
	}

	return result
}

func ptrString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ptrInt32(i int32) *int32 {
	return &i
}

func ptrBool(b bool) *bool {
	return &b
}

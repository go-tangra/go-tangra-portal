package data

import (
	"context"
	"net"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/subnet"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

type SubnetRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewSubnetRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *SubnetRepo {
	return &SubnetRepo{
		log:       ctx.NewLoggerHelper("ipam/subnet/repo"),
		entClient: entClient,
	}
}

// Create creates a new subnet
func (r *SubnetRepo) Create(ctx context.Context, tenantID uint32, name, cidr string, opts ...func(*ent.SubnetCreate)) (*ent.Subnet, error) {
	id := uuid.New().String()

	// Parse CIDR to get network info
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, ipamV1.ErrorSubnetCidrInvalid("invalid CIDR: %s", cidr)
	}

	// Calculate network properties
	ipVersion := 4
	if ipNet.IP.To4() == nil {
		ipVersion = 6
	}

	networkAddr := ipNet.IP.String()
	prefixLen, _ := ipNet.Mask.Size()
	mask := net.IP(ipNet.Mask).String()

	// Calculate total addresses
	var totalAddresses int64
	if ipVersion == 4 {
		totalAddresses = 1 << (32 - prefixLen)
	} else {
		// For IPv6, limit to a reasonable number
		if prefixLen <= 64 {
			totalAddresses = int64(^uint64(0) >> 1) // Max int64 for display
		} else if prefixLen < 128 {
			totalAddresses = int64(1) << (128 - prefixLen)
		} else {
			totalAddresses = 1
		}
	}

	// Calculate broadcast (IPv4 only)
	var broadcastAddr string
	if ipVersion == 4 {
		broadcast := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
		}
		broadcastAddr = broadcast.String()
	}

	create := r.entClient.Client().Subnet.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetCidr(cidr).
		SetIPVersion(int32(ipVersion)).
		SetNetworkAddress(networkAddr).
		SetBroadcastAddress(broadcastAddr).
		SetMask(mask).
		SetPrefixLength(int32(prefixLen)).
		SetTotalAddresses(totalAddresses).
		SetStatus(1). // Active
		SetCreateTime(time.Now())

	// Apply optional settings
	for _, opt := range opts {
		opt(create)
	}

	entity, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ipamV1.ErrorSubnetAlreadyExists("subnet with name '%s' already exists", name)
		}
		r.log.Errorf("create subnet failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create subnet failed")
	}

	return entity, nil
}

// GetByID retrieves a subnet by ID
func (r *SubnetRepo) GetByID(ctx context.Context, id string) (*ent.Subnet, error) {
	entity, err := r.entClient.Client().Subnet.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get subnet failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get subnet failed")
	}
	return entity, nil
}

// GetByTenantAndName retrieves a subnet by tenant and name
func (r *SubnetRepo) GetByTenantAndName(ctx context.Context, tenantID uint32, name string) (*ent.Subnet, error) {
	entity, err := r.entClient.Client().Subnet.Query().
		Where(
			subnet.TenantID(tenantID),
			subnet.Name(name),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get subnet by name failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get subnet failed")
	}
	return entity, nil
}

// List lists subnets with filtering
func (r *SubnetRepo) List(ctx context.Context, tenantID uint32, page, pageSize int, filters map[string]interface{}) ([]*ent.Subnet, int, error) {
	query := r.entClient.Client().Subnet.Query().
		Where(subnet.TenantID(tenantID))

	// Apply filters
	if vlanID, ok := filters["vlan_id"].(string); ok && vlanID != "" {
		query = query.Where(subnet.VlanID(vlanID))
	}
	if parentID, ok := filters["parent_id"].(string); ok && parentID != "" {
		query = query.Where(subnet.ParentID(parentID))
	}
	if locationID, ok := filters["location_id"].(string); ok && locationID != "" {
		query = query.Where(subnet.LocationID(locationID))
	}
	if status, ok := filters["status"].(int32); ok && status > 0 {
		query = query.Where(subnet.Status(status))
	}
	if ipVersion, ok := filters["ip_version"].(int32); ok && ipVersion > 0 {
		query = query.Where(subnet.IPVersion(ipVersion))
	}

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count subnets failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list subnets failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	// Order by create time descending
	query = query.Order(ent.Desc(subnet.FieldCreateTime))

	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list subnets failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list subnets failed")
	}

	return entities, total, nil
}

// Update updates a subnet
func (r *SubnetRepo) Update(ctx context.Context, id string, updates map[string]interface{}) (*ent.Subnet, error) {
	update := r.entClient.Client().Subnet.UpdateOneID(id)

	if name, ok := updates["name"].(string); ok {
		update = update.SetName(name)
	}
	if description, ok := updates["description"].(string); ok {
		update = update.SetDescription(description)
	}
	if gateway, ok := updates["gateway"].(string); ok {
		update = update.SetGateway(gateway)
	}
	if dnsServers, ok := updates["dns_servers"].(string); ok {
		update = update.SetDNSServers(dnsServers)
	}
	if vlanID, ok := updates["vlan_id"].(string); ok {
		update = update.SetVlanID(vlanID)
	}
	if locationID, ok := updates["location_id"].(string); ok {
		update = update.SetLocationID(locationID)
	}
	if status, ok := updates["status"].(int32); ok {
		update = update.SetStatus(status)
	}
	if tags, ok := updates["tags"].(string); ok {
		update = update.SetTags(tags)
	}
	if metadata, ok := updates["metadata"].(string); ok {
		update = update.SetMetadata(metadata)
	}

	update = update.SetUpdateTime(time.Now())

	entity, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorSubnetNotFound("subnet not found")
		}
		r.log.Errorf("update subnet failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update subnet failed")
	}

	return entity, nil
}

// Delete deletes a subnet
func (r *SubnetRepo) Delete(ctx context.Context, id string, force bool) error {
	// Get the subnet to check if it has a parent
	subnetEntity, err := r.entClient.Client().Subnet.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorSubnetNotFound("subnet not found")
		}
		r.log.Errorf("get subnet failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete subnet failed")
	}

	// Get all IP addresses in this subnet
	addresses, err := r.entClient.Client().Subnet.Query().
		Where(subnet.ID(id)).
		QueryAddresses().
		All(ctx)
	if err != nil {
		r.log.Errorf("get subnet addresses failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete subnet failed")
	}

	// Check if deletion is allowed without force
	if !force && len(addresses) > 0 {
		return ipamV1.ErrorSubnetHasAddresses("subnet has %d addresses, use force to delete", len(addresses))
	}

	// Handle IP addresses based on whether subnet has a parent
	if len(addresses) > 0 {
		if subnetEntity.ParentID != "" {
			// Has parent - reassign IPs to parent subnet
			for _, addr := range addresses {
				err := r.entClient.Client().IpAddress.UpdateOneID(addr.ID).
					SetSubnetID(subnetEntity.ParentID).
					SetUpdateTime(time.Now()).
					Exec(ctx)
				if err != nil {
					r.log.Warnf("failed to reassign IP %s to parent subnet: %s", addr.Address, err.Error())
				}
			}
			r.log.Infof("reassigned %d IP addresses from subnet %s to parent %s", len(addresses), id, subnetEntity.ParentID)
		} else {
			// No parent - delete the IPs
			for _, addr := range addresses {
				err := r.entClient.Client().IpAddress.DeleteOneID(addr.ID).Exec(ctx)
				if err != nil {
					r.log.Warnf("failed to delete IP %s: %s", addr.Address, err.Error())
				}
			}
			r.log.Infof("deleted %d IP addresses from root subnet %s", len(addresses), id)
		}
	}

	// Delete the subnet
	err = r.entClient.Client().Subnet.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorSubnetNotFound("subnet not found")
		}
		r.log.Errorf("delete subnet failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete subnet failed")
	}

	return nil
}

// GetTree retrieves all subnets for building tree hierarchy
func (r *SubnetRepo) GetTree(ctx context.Context, tenantID uint32, rootID string, maxDepth int) ([]*ent.Subnet, error) {
	query := r.entClient.Client().Subnet.Query().
		Where(subnet.TenantID(tenantID)).
		Order(ent.Asc(subnet.FieldCidr))

	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("get subnet tree failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get subnet tree failed")
	}

	return entities, nil
}

// GetStats retrieves subnet utilization statistics
func (r *SubnetRepo) GetStats(ctx context.Context, id string) (total, used, available int64, err error) {
	entity, err := r.entClient.Client().Subnet.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return 0, 0, 0, ipamV1.ErrorSubnetNotFound("subnet not found")
		}
		r.log.Errorf("get subnet stats failed: %s", err.Error())
		return 0, 0, 0, ipamV1.ErrorInternalServerError("get subnet stats failed")
	}

	total = entity.TotalAddresses

	// Count used addresses
	usedCount, err := r.entClient.Client().Subnet.Query().
		Where(subnet.ID(id)).
		QueryAddresses().
		Count(ctx)
	if err != nil {
		r.log.Errorf("count subnet addresses failed: %s", err.Error())
		return 0, 0, 0, ipamV1.ErrorInternalServerError("get subnet stats failed")
	}
	used = int64(usedCount)

	available = total - used
	if available < 0 {
		available = 0
	}

	return total, int64(used), available, nil
}

// ReassignIPsFromParentToChild moves IP addresses from a parent subnet to a child subnet
// if they fall within the child's CIDR range
func (r *SubnetRepo) ReassignIPsFromParentToChild(ctx context.Context, parentID, childID, childCIDR string) (int, error) {
	// Parse the child's CIDR to determine the IP range
	_, childNet, err := net.ParseCIDR(childCIDR)
	if err != nil {
		return 0, ipamV1.ErrorSubnetCidrInvalid("invalid child CIDR: %s", childCIDR)
	}

	// Get all IP addresses in the parent subnet
	addresses, err := r.entClient.Client().Subnet.Query().
		Where(subnet.ID(parentID)).
		QueryAddresses().
		All(ctx)
	if err != nil {
		r.log.Errorf("failed to get parent subnet addresses: %s", err.Error())
		return 0, ipamV1.ErrorInternalServerError("failed to get parent subnet addresses")
	}

	// Filter and update addresses that fall within the child subnet
	reassignedCount := 0
	for _, addr := range addresses {
		ip := net.ParseIP(addr.Address)
		if ip == nil {
			continue
		}

		// Check if this IP falls within the child subnet's range
		if childNet.Contains(ip) {
			// Update the IP to point to the child subnet
			err := r.entClient.Client().IpAddress.UpdateOneID(addr.ID).
				SetSubnetID(childID).
				SetUpdateTime(time.Now()).
				Exec(ctx)
			if err != nil {
				r.log.Warnf("failed to reassign IP %s to child subnet: %s", addr.Address, err.Error())
				continue
			}
			reassignedCount++
		}
	}

	if reassignedCount > 0 {
		r.log.Infof("reassigned %d IP addresses from parent %s to child %s", reassignedCount, parentID, childID)
	}

	return reassignedCount, nil
}

// CheckCIDROverlap checks if a CIDR overlaps with existing subnets
func (r *SubnetRepo) CheckCIDROverlap(ctx context.Context, tenantID uint32, cidr string, excludeID string) (bool, error) {
	_, newNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, ipamV1.ErrorSubnetCidrInvalid("invalid CIDR: %s", cidr)
	}

	// Get all subnets for tenant
	query := r.entClient.Client().Subnet.Query().
		Where(subnet.TenantID(tenantID))

	if excludeID != "" {
		query = query.Where(subnet.IDNEQ(excludeID))
	}

	subnets, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("check CIDR overlap failed: %s", err.Error())
		return false, ipamV1.ErrorInternalServerError("check CIDR overlap failed")
	}

	for _, s := range subnets {
		_, existingNet, err := net.ParseCIDR(s.Cidr)
		if err != nil {
			continue
		}

		// Check if networks overlap
		if newNet.Contains(existingNet.IP) || existingNet.Contains(newNet.IP) {
			return true, nil
		}
	}

	return false, nil
}

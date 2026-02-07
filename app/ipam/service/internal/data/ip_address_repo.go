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
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/ipaddress"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

type IpAddressRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewIpAddressRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *IpAddressRepo {
	return &IpAddressRepo{
		log:       ctx.NewLoggerHelper("ipam/ip_address/repo"),
		entClient: entClient,
	}
}

func (r *IpAddressRepo) Create(ctx context.Context, tenantID uint32, address, subnetID string, opts ...func(*ent.IpAddressCreate)) (*ent.IpAddress, error) {
	id := uuid.New().String()

	// Validate IP address
	if ip := net.ParseIP(address); ip == nil {
		return nil, ipamV1.ErrorAddressInvalid("invalid IP address: %s", address)
	}

	create := r.entClient.Client().IpAddress.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetAddress(address).
		SetSubnetID(subnetID).
		SetStatus(1).
		SetAddressType(1).
		SetCreateTime(time.Now())

	for _, opt := range opts {
		opt(create)
	}

	entity, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ipamV1.ErrorAddressAlreadyExists("address '%s' already exists", address)
		}
		r.log.Errorf("create ip address failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create ip address failed")
	}
	return entity, nil
}

func (r *IpAddressRepo) GetByID(ctx context.Context, id string) (*ent.IpAddress, error) {
	entity, err := r.entClient.Client().IpAddress.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get ip address failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get ip address failed")
	}
	return entity, nil
}

func (r *IpAddressRepo) GetByAddress(ctx context.Context, tenantID uint32, address string) (*ent.IpAddress, error) {
	entity, err := r.entClient.Client().IpAddress.Query().
		Where(ipaddress.TenantID(tenantID), ipaddress.Address(address)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get ip address by address failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get ip address failed")
	}
	return entity, nil
}

func (r *IpAddressRepo) List(ctx context.Context, tenantID uint32, page, pageSize int, filters map[string]interface{}) ([]*ent.IpAddress, int, error) {
	query := r.entClient.Client().IpAddress.Query().Where(ipaddress.TenantID(tenantID))

	// Check if we should filter by CIDR range (includes orphaned IPs)
	if cidr, ok := filters["cidr"].(string); ok && cidr != "" {
		// Parse CIDR to get IP range
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			// Get all IPs and filter in memory by CIDR range
			// This is necessary because SQL doesn't have built-in CIDR matching
			// For large datasets, consider using database-specific IP range functions
			allQuery := r.entClient.Client().IpAddress.Query().Where(ipaddress.TenantID(tenantID))

			if deviceID, ok := filters["device_id"].(string); ok && deviceID != "" {
				allQuery = allQuery.Where(ipaddress.DeviceID(deviceID))
			}
			if status, ok := filters["status"].(int32); ok && status > 0 {
				allQuery = allQuery.Where(ipaddress.Status(status))
			}

			allEntities, err := allQuery.Order(ent.Asc(ipaddress.FieldAddress)).All(ctx)
			if err != nil {
				r.log.Errorf("list ip addresses failed: %s", err.Error())
				return nil, 0, ipamV1.ErrorInternalServerError("list ip addresses failed")
			}

			// Filter by CIDR range
			var filtered []*ent.IpAddress
			for _, e := range allEntities {
				ip := net.ParseIP(e.Address)
				if ip != nil && ipNet.Contains(ip) {
					filtered = append(filtered, e)
				}
			}

			total := len(filtered)

			// Apply pagination
			if page > 0 && pageSize > 0 {
				start := (page - 1) * pageSize
				end := start + pageSize
				if start >= len(filtered) {
					return []*ent.IpAddress{}, total, nil
				}
				if end > len(filtered) {
					end = len(filtered)
				}
				filtered = filtered[start:end]
			}

			return filtered, total, nil
		}
	}

	// Standard subnet_id based filtering
	if subnetID, ok := filters["subnet_id"].(string); ok && subnetID != "" {
		query = query.Where(ipaddress.SubnetID(subnetID))
	}
	if deviceID, ok := filters["device_id"].(string); ok && deviceID != "" {
		query = query.Where(ipaddress.DeviceID(deviceID))
	}
	if status, ok := filters["status"].(int32); ok && status > 0 {
		query = query.Where(ipaddress.Status(status))
	}

	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count ip addresses failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list ip addresses failed")
	}

	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	entities, err := query.Order(ent.Asc(ipaddress.FieldAddress)).All(ctx)
	if err != nil {
		r.log.Errorf("list ip addresses failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list ip addresses failed")
	}

	return entities, total, nil
}

func (r *IpAddressRepo) Update(ctx context.Context, id string, updates map[string]interface{}) (*ent.IpAddress, error) {
	update := r.entClient.Client().IpAddress.UpdateOneID(id)

	if hostname, ok := updates["hostname"].(string); ok {
		update = update.SetHostname(hostname)
	}
	if macAddress, ok := updates["mac_address"].(string); ok {
		update = update.SetMACAddress(macAddress)
	}
	if description, ok := updates["description"].(string); ok {
		update = update.SetDescription(description)
	}
	if deviceID, ok := updates["device_id"].(string); ok {
		update = update.SetDeviceID(deviceID)
	}
	if status, ok := updates["status"].(int32); ok {
		update = update.SetStatus(status)
	}
	if lastSeen, ok := updates["last_seen"].(time.Time); ok {
		update = update.SetLastSeen(lastSeen)
	}
	if hasReverseDNS, ok := updates["has_reverse_dns"].(bool); ok {
		update = update.SetHasReverseDNS(hasReverseDNS)
	}

	update = update.SetUpdateTime(time.Now())

	entity, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorAddressNotFound("address not found")
		}
		r.log.Errorf("update ip address failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update ip address failed")
	}
	return entity, nil
}

func (r *IpAddressRepo) Delete(ctx context.Context, id string) error {
	err := r.entClient.Client().IpAddress.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorAddressNotFound("address not found")
		}
		r.log.Errorf("delete ip address failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete ip address failed")
	}
	return nil
}

// AllocateNext finds and allocates the next available IP in a subnet
func (r *IpAddressRepo) AllocateNext(ctx context.Context, tenantID uint32, subnetID string) (string, error) {
	// This is a simplified implementation - a real one would need to:
	// 1. Get the subnet CIDR
	// 2. Enumerate all possible IPs
	// 3. Find the first unallocated one
	// For now, return an error indicating this needs more implementation
	return "", ipamV1.ErrorInternalServerError("allocate next not yet implemented")
}

package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/device"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/hostgroup"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/hostgroupmember"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

type HostGroupRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewHostGroupRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *HostGroupRepo {
	return &HostGroupRepo{
		log:       ctx.NewLoggerHelper("ipam/host-group/repo"),
		entClient: entClient,
	}
}

// Create creates a new host group
func (r *HostGroupRepo) Create(ctx context.Context, tenantID uint32, name string, opts ...func(*ent.HostGroupCreate)) (*ent.HostGroup, error) {
	id := uuid.New().String()

	create := r.entClient.Client().HostGroup.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetStatus(1). // Active
		SetCreateTime(time.Now())

	// Apply optional settings
	for _, opt := range opts {
		opt(create)
	}

	entity, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ipamV1.ErrorHostGroupAlreadyExists("Host group with name '%s' already exists", name)
		}
		r.log.Errorf("create host group failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create host group failed")
	}

	return entity, nil
}

// GetByID retrieves a host group by ID
func (r *HostGroupRepo) GetByID(ctx context.Context, id string) (*ent.HostGroup, error) {
	entity, err := r.entClient.Client().HostGroup.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get host group failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get host group failed")
	}
	return entity, nil
}

// GetByTenantAndName retrieves a host group by tenant and name
func (r *HostGroupRepo) GetByTenantAndName(ctx context.Context, tenantID uint32, name string) (*ent.HostGroup, error) {
	entity, err := r.entClient.Client().HostGroup.Query().
		Where(
			hostgroup.TenantID(tenantID),
			hostgroup.Name(name),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get host group by name failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get host group failed")
	}
	return entity, nil
}

// List lists host groups with filtering
func (r *HostGroupRepo) List(ctx context.Context, tenantID uint32, page, pageSize int, filters map[string]interface{}) ([]*ent.HostGroup, int, error) {
	query := r.entClient.Client().HostGroup.Query().
		Where(hostgroup.TenantID(tenantID))

	// Apply filters
	if status, ok := filters["status"].(int32); ok && status > 0 {
		query = query.Where(hostgroup.Status(status))
	}
	if queryStr, ok := filters["query"].(string); ok && queryStr != "" {
		query = query.Where(hostgroup.NameContainsFold(queryStr))
	}

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count host groups failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list host groups failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	// Order by create time descending
	query = query.Order(ent.Desc(hostgroup.FieldCreateTime))

	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list host groups failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list host groups failed")
	}

	return entities, total, nil
}

// Update updates a host group
func (r *HostGroupRepo) Update(ctx context.Context, id string, updates map[string]interface{}) (*ent.HostGroup, error) {
	update := r.entClient.Client().HostGroup.UpdateOneID(id)

	if name, ok := updates["name"].(string); ok {
		update = update.SetName(name)
	}
	if description, ok := updates["description"].(string); ok {
		update = update.SetDescription(description)
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
			return nil, ipamV1.ErrorHostGroupNotFound("Host group not found")
		}
		r.log.Errorf("update host group failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update host group failed")
	}

	return entity, nil
}

// Delete deletes a host group and its members
func (r *HostGroupRepo) Delete(ctx context.Context, id string) error {
	// Delete all members first
	_, err := r.entClient.Client().HostGroupMember.Delete().
		Where(hostgroupmember.HostGroupID(id)).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete host group members failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete host group failed")
	}

	// Delete the group
	err = r.entClient.Client().HostGroup.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorHostGroupNotFound("Host group not found")
		}
		r.log.Errorf("delete host group failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete host group failed")
	}

	return nil
}

// GetMemberCount returns the number of members in a host group
func (r *HostGroupRepo) GetMemberCount(ctx context.Context, id string) (int, error) {
	count, err := r.entClient.Client().HostGroupMember.Query().
		Where(hostgroupmember.HostGroupID(id)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count host group members failed: %s", err.Error())
		return 0, ipamV1.ErrorInternalServerError("count host group members failed")
	}
	return count, nil
}

// AddMember adds a device to a host group
func (r *HostGroupRepo) AddMember(ctx context.Context, groupID, deviceID string, sequence int32) (*ent.HostGroupMember, error) {
	// Verify device exists
	deviceExists, err := r.entClient.Client().Device.Query().
		Where(device.ID(deviceID)).
		Exist(ctx)
	if err != nil {
		r.log.Errorf("check device existence failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("add host group member failed")
	}
	if !deviceExists {
		return nil, ipamV1.ErrorDeviceNotFound("Device not found: %s", deviceID)
	}

	id := uuid.New().String()

	create := r.entClient.Client().HostGroupMember.Create().
		SetID(id).
		SetHostGroupID(groupID).
		SetDeviceID(deviceID).
		SetSequence(sequence).
		SetCreateTime(time.Now())

	entity, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ipamV1.ErrorHostGroupMemberDuplicate("Device '%s' already exists in this group", deviceID)
		}
		r.log.Errorf("add host group member failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("add host group member failed")
	}

	return entity, nil
}

// RemoveMember removes a device from a host group
func (r *HostGroupRepo) RemoveMember(ctx context.Context, groupID, memberID string) error {
	// Verify member belongs to group
	member, err := r.entClient.Client().HostGroupMember.Query().
		Where(
			hostgroupmember.ID(memberID),
			hostgroupmember.HostGroupID(groupID),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorHostGroupMemberNotFound("Member not found in this group")
		}
		r.log.Errorf("get host group member failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("remove host group member failed")
	}

	err = r.entClient.Client().HostGroupMember.DeleteOneID(member.ID).Exec(ctx)
	if err != nil {
		r.log.Errorf("delete host group member failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("remove host group member failed")
	}

	return nil
}

// ListMembers lists members of a host group with device details
func (r *HostGroupRepo) ListMembers(ctx context.Context, groupID string, page, pageSize int) ([]*ent.HostGroupMember, int, error) {
	query := r.entClient.Client().HostGroupMember.Query().
		Where(hostgroupmember.HostGroupID(groupID)).
		WithDevice()

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count host group members failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list host group members failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	// Order by sequence, then create time
	query = query.Order(ent.Asc(hostgroupmember.FieldSequence), ent.Asc(hostgroupmember.FieldCreateTime))

	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list host group members failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list host group members failed")
	}

	return entities, total, nil
}

// UpdateMember updates a member's sequence in a host group
func (r *HostGroupRepo) UpdateMember(ctx context.Context, groupID, memberID string, sequence *int32) (*ent.HostGroupMember, error) {
	// Verify member belongs to group
	_, err := r.entClient.Client().HostGroupMember.Query().
		Where(
			hostgroupmember.ID(memberID),
			hostgroupmember.HostGroupID(groupID),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorHostGroupMemberNotFound("Member not found in this group")
		}
		r.log.Errorf("get host group member failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update host group member failed")
	}

	update := r.entClient.Client().HostGroupMember.UpdateOneID(memberID)

	if sequence != nil {
		update = update.SetSequence(*sequence)
	}

	update = update.SetUpdateTime(time.Now())

	entity, err := update.Save(ctx)
	if err != nil {
		r.log.Errorf("update host group member failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update host group member failed")
	}

	return entity, nil
}

// ListGroupsForDevice lists all groups a device belongs to
func (r *HostGroupRepo) ListGroupsForDevice(ctx context.Context, tenantID uint32, deviceID string) ([]*ent.HostGroup, error) {
	// Get all member records for this device
	members, err := r.entClient.Client().HostGroupMember.Query().
		Where(hostgroupmember.DeviceID(deviceID)).
		All(ctx)
	if err != nil {
		r.log.Errorf("list device memberships failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("list device host groups failed")
	}

	if len(members) == 0 {
		return []*ent.HostGroup{}, nil
	}

	// Get group IDs
	groupIDs := make([]string, len(members))
	for i, m := range members {
		groupIDs[i] = m.HostGroupID
	}

	// Fetch groups
	query := r.entClient.Client().HostGroup.Query().
		Where(hostgroup.IDIn(groupIDs...))

	if tenantID > 0 {
		query = query.Where(hostgroup.TenantID(tenantID))
	}

	groups, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list host groups for device failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("list device host groups failed")
	}

	return groups, nil
}

// RemoveDeviceFromAllGroups removes a device from all host groups
// This should be called when a device is deleted
func (r *HostGroupRepo) RemoveDeviceFromAllGroups(ctx context.Context, deviceID string) error {
	_, err := r.entClient.Client().HostGroupMember.Delete().
		Where(hostgroupmember.DeviceID(deviceID)).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("remove device from all groups failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("remove device from groups failed")
	}
	return nil
}

// GetMemberByDeviceID gets a member by group ID and device ID
func (r *HostGroupRepo) GetMemberByDeviceID(ctx context.Context, groupID, deviceID string) (*ent.HostGroupMember, error) {
	member, err := r.entClient.Client().HostGroupMember.Query().
		Where(
			hostgroupmember.HostGroupID(groupID),
			hostgroupmember.DeviceID(deviceID),
		).
		WithDevice().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get host group member by device failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get host group member failed")
	}
	return member, nil
}

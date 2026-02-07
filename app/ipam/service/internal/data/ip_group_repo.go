package data

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/ipgroup"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/ipgroupmember"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

type IpGroupRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewIpGroupRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *IpGroupRepo {
	return &IpGroupRepo{
		log:       ctx.NewLoggerHelper("ipam/ip-group/repo"),
		entClient: entClient,
	}
}

// Create creates a new IP group
func (r *IpGroupRepo) Create(ctx context.Context, tenantID uint32, name string, opts ...func(*ent.IpGroupCreate)) (*ent.IpGroup, error) {
	id := uuid.New().String()

	create := r.entClient.Client().IpGroup.Create().
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
			return nil, ipamV1.ErrorIpGroupAlreadyExists("IP group with name '%s' already exists", name)
		}
		r.log.Errorf("create IP group failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create IP group failed")
	}

	return entity, nil
}

// GetByID retrieves an IP group by ID
func (r *IpGroupRepo) GetByID(ctx context.Context, id string) (*ent.IpGroup, error) {
	entity, err := r.entClient.Client().IpGroup.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get IP group failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get IP group failed")
	}
	return entity, nil
}

// GetByTenantAndName retrieves an IP group by tenant and name
func (r *IpGroupRepo) GetByTenantAndName(ctx context.Context, tenantID uint32, name string) (*ent.IpGroup, error) {
	entity, err := r.entClient.Client().IpGroup.Query().
		Where(
			ipgroup.TenantID(tenantID),
			ipgroup.Name(name),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get IP group by name failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get IP group failed")
	}
	return entity, nil
}

// List lists IP groups with filtering
func (r *IpGroupRepo) List(ctx context.Context, tenantID uint32, page, pageSize int, filters map[string]interface{}) ([]*ent.IpGroup, int, error) {
	query := r.entClient.Client().IpGroup.Query().
		Where(ipgroup.TenantID(tenantID))

	// Apply filters
	if status, ok := filters["status"].(int32); ok && status > 0 {
		query = query.Where(ipgroup.Status(status))
	}
	if queryStr, ok := filters["query"].(string); ok && queryStr != "" {
		query = query.Where(ipgroup.NameContainsFold(queryStr))
	}

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count IP groups failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list IP groups failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	// Order by create time descending
	query = query.Order(ent.Desc(ipgroup.FieldCreateTime))

	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list IP groups failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list IP groups failed")
	}

	return entities, total, nil
}

// Update updates an IP group
func (r *IpGroupRepo) Update(ctx context.Context, id string, updates map[string]interface{}) (*ent.IpGroup, error) {
	update := r.entClient.Client().IpGroup.UpdateOneID(id)

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
			return nil, ipamV1.ErrorIpGroupNotFound("IP group not found")
		}
		r.log.Errorf("update IP group failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update IP group failed")
	}

	return entity, nil
}

// Delete deletes an IP group and its members
func (r *IpGroupRepo) Delete(ctx context.Context, id string) error {
	// Delete all members first
	_, err := r.entClient.Client().IpGroupMember.Delete().
		Where(ipgroupmember.IPGroupID(id)).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete IP group members failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete IP group failed")
	}

	// Delete the group
	err = r.entClient.Client().IpGroup.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorIpGroupNotFound("IP group not found")
		}
		r.log.Errorf("delete IP group failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete IP group failed")
	}

	return nil
}

// GetMemberCount returns the number of members in an IP group
func (r *IpGroupRepo) GetMemberCount(ctx context.Context, id string) (int, error) {
	count, err := r.entClient.Client().IpGroupMember.Query().
		Where(ipgroupmember.IPGroupID(id)).
		Count(ctx)
	if err != nil {
		r.log.Errorf("count IP group members failed: %s", err.Error())
		return 0, ipamV1.ErrorInternalServerError("count IP group members failed")
	}
	return count, nil
}

// AddMember adds a member to an IP group
func (r *IpGroupRepo) AddMember(ctx context.Context, groupID string, memberType int32, value, description string, sequence int32) (*ent.IpGroupMember, error) {
	// Validate member value
	if err := ValidateMemberValue(memberType, value); err != nil {
		return nil, err
	}

	id := uuid.New().String()

	create := r.entClient.Client().IpGroupMember.Create().
		SetID(id).
		SetIPGroupID(groupID).
		SetMemberType(memberType).
		SetValue(value).
		SetSequence(sequence).
		SetCreateTime(time.Now())

	if description != "" {
		create = create.SetDescription(description)
	}

	entity, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ipamV1.ErrorIpGroupMemberDuplicate("member '%s' already exists in this group", value)
		}
		r.log.Errorf("add IP group member failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("add IP group member failed")
	}

	return entity, nil
}

// RemoveMember removes a member from an IP group
func (r *IpGroupRepo) RemoveMember(ctx context.Context, groupID, memberID string) error {
	// Verify member belongs to group
	member, err := r.entClient.Client().IpGroupMember.Query().
		Where(
			ipgroupmember.ID(memberID),
			ipgroupmember.IPGroupID(groupID),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorIpGroupMemberNotFound("member not found in this group")
		}
		r.log.Errorf("get IP group member failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("remove IP group member failed")
	}

	err = r.entClient.Client().IpGroupMember.DeleteOneID(member.ID).Exec(ctx)
	if err != nil {
		r.log.Errorf("delete IP group member failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("remove IP group member failed")
	}

	return nil
}

// ListMembers lists members of an IP group
func (r *IpGroupRepo) ListMembers(ctx context.Context, groupID string, page, pageSize int) ([]*ent.IpGroupMember, int, error) {
	query := r.entClient.Client().IpGroupMember.Query().
		Where(ipgroupmember.IPGroupID(groupID))

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count IP group members failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list IP group members failed")
	}

	// Apply pagination
	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	// Order by sequence, then create time
	query = query.Order(ent.Asc(ipgroupmember.FieldSequence), ent.Asc(ipgroupmember.FieldCreateTime))

	entities, err := query.All(ctx)
	if err != nil {
		r.log.Errorf("list IP group members failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list IP group members failed")
	}

	return entities, total, nil
}

// UpdateMember updates a member in an IP group
func (r *IpGroupRepo) UpdateMember(ctx context.Context, groupID, memberID string, description *string, sequence *int32) (*ent.IpGroupMember, error) {
	// Verify member belongs to group
	_, err := r.entClient.Client().IpGroupMember.Query().
		Where(
			ipgroupmember.ID(memberID),
			ipgroupmember.IPGroupID(groupID),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorIpGroupMemberNotFound("member not found in this group")
		}
		r.log.Errorf("get IP group member failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update IP group member failed")
	}

	update := r.entClient.Client().IpGroupMember.UpdateOneID(memberID)

	if description != nil {
		update = update.SetDescription(*description)
	}
	if sequence != nil {
		update = update.SetSequence(*sequence)
	}

	update = update.SetUpdateTime(time.Now())

	entity, err := update.Save(ctx)
	if err != nil {
		r.log.Errorf("update IP group member failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update IP group member failed")
	}

	return entity, nil
}

// CheckIpInGroups checks if an IP address is contained in any groups
func (r *IpGroupRepo) CheckIpInGroups(ctx context.Context, tenantID uint32, ipAddress string, groupIDs []string) ([]*ent.IpGroup, error) {
	// Parse the IP address
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, ipamV1.ErrorAddressInvalid("invalid IP address: %s", ipAddress)
	}

	// Get all groups (optionally filtered by IDs)
	groupQuery := r.entClient.Client().IpGroup.Query().
		Where(ipgroup.TenantID(tenantID))

	if len(groupIDs) > 0 {
		groupQuery = groupQuery.Where(ipgroup.IDIn(groupIDs...))
	}

	groups, err := groupQuery.All(ctx)
	if err != nil {
		r.log.Errorf("list IP groups failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("check IP in groups failed")
	}

	var matchingGroups []*ent.IpGroup

	for _, group := range groups {
		// Get members of this group
		members, err := r.entClient.Client().IpGroupMember.Query().
			Where(ipgroupmember.IPGroupID(group.ID)).
			All(ctx)
		if err != nil {
			continue
		}

		// Check if IP matches any member
		for _, member := range members {
			if ipMatchesMember(ip, member.MemberType, member.Value) {
				matchingGroups = append(matchingGroups, group)
				break // Found match in this group, move to next group
			}
		}
	}

	return matchingGroups, nil
}

// ValidateMemberValue validates the member value based on type
func ValidateMemberValue(memberType int32, value string) error {
	switch memberType {
	case 1: // ADDRESS
		ip := net.ParseIP(value)
		if ip == nil {
			return ipamV1.ErrorIpGroupMemberInvalid("invalid IP address: %s", value)
		}
	case 2: // RANGE
		parts := strings.Split(value, "-")
		if len(parts) != 2 {
			return ipamV1.ErrorIpGroupMemberInvalid("invalid IP range format, expected 'start-end': %s", value)
		}
		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))
		if startIP == nil || endIP == nil {
			return ipamV1.ErrorIpGroupMemberInvalid("invalid IP addresses in range: %s", value)
		}
		// Validate start <= end
		if !ipLessOrEqual(startIP, endIP) {
			return ipamV1.ErrorIpGroupMemberInvalid("range start must be <= end: %s", value)
		}
	case 3: // SUBNET
		_, _, err := net.ParseCIDR(value)
		if err != nil {
			return ipamV1.ErrorIpGroupMemberInvalid("invalid CIDR format: %s", value)
		}
	default:
		return ipamV1.ErrorIpGroupMemberInvalid("unknown member type: %d", memberType)
	}
	return nil
}

// ipMatchesMember checks if an IP address matches a member
func ipMatchesMember(ip net.IP, memberType int32, value string) bool {
	switch memberType {
	case 1: // ADDRESS
		memberIP := net.ParseIP(value)
		return memberIP != nil && ip.Equal(memberIP)
	case 2: // RANGE
		parts := strings.Split(value, "-")
		if len(parts) != 2 {
			return false
		}
		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))
		if startIP == nil || endIP == nil {
			return false
		}
		return ipInRange(ip, startIP, endIP)
	case 3: // SUBNET
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		return ipNet.Contains(ip)
	}
	return false
}

// ipInRange checks if an IP is within a range
func ipInRange(ip, start, end net.IP) bool {
	// Normalize to 16-byte representation
	ip = ip.To16()
	start = start.To16()
	end = end.To16()

	if ip == nil || start == nil || end == nil {
		return false
	}

	return ipLessOrEqual(start, ip) && ipLessOrEqual(ip, end)
}

// ipLessOrEqual compares two IPs
func ipLessOrEqual(a, b net.IP) bool {
	a = a.To16()
	b = b.To16()

	if a == nil || b == nil {
		return false
	}

	for i := 0; i < 16; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return true // equal
}

// IP range regex for validation
var ipRangeRegex = regexp.MustCompile(`^[\d.:]+\s*-\s*[\d.:]+$`)

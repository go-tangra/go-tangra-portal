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
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

type DeviceRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewDeviceRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *DeviceRepo {
	return &DeviceRepo{
		log:       ctx.NewLoggerHelper("ipam/device/repo"),
		entClient: entClient,
	}
}

func (r *DeviceRepo) Create(ctx context.Context, tenantID uint32, name string, opts ...func(*ent.DeviceCreate)) (*ent.Device, error) {
	id := uuid.New().String()

	create := r.entClient.Client().Device.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetStatus(1).
		SetCreateTime(time.Now())

	for _, opt := range opts {
		opt(create)
	}

	entity, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ipamV1.ErrorDeviceAlreadyExists("device '%s' already exists", name)
		}
		r.log.Errorf("create device failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create device failed")
	}
	return entity, nil
}

func (r *DeviceRepo) GetByID(ctx context.Context, id string) (*ent.Device, error) {
	entity, err := r.entClient.Client().Device.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get device failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get device failed")
	}
	return entity, nil
}

func (r *DeviceRepo) List(ctx context.Context, tenantID uint32, page, pageSize int, filters map[string]interface{}) ([]*ent.Device, int, error) {
	query := r.entClient.Client().Device.Query().Where(device.TenantID(tenantID))

	if deviceType, ok := filters["device_type"].(int32); ok && deviceType > 0 {
		query = query.Where(device.DeviceType(deviceType))
	}
	if status, ok := filters["status"].(int32); ok && status > 0 {
		query = query.Where(device.Status(status))
	}
	if locationID, ok := filters["location_id"].(string); ok && locationID != "" {
		query = query.Where(device.LocationID(locationID))
	}

	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count devices failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list devices failed")
	}

	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	entities, err := query.Order(ent.Asc(device.FieldName)).All(ctx)
	if err != nil {
		r.log.Errorf("list devices failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list devices failed")
	}

	return entities, total, nil
}

func (r *DeviceRepo) Update(ctx context.Context, id string, updates map[string]interface{}) (*ent.Device, error) {
	update := r.entClient.Client().Device.UpdateOneID(id)

	if name, ok := updates["name"].(string); ok {
		update = update.SetName(name)
	}
	if description, ok := updates["description"].(string); ok {
		update = update.SetDescription(description)
	}
	if status, ok := updates["status"].(int32); ok {
		update = update.SetStatus(status)
	}
	if primaryIP, ok := updates["primary_ip"].(string); ok {
		update = update.SetPrimaryIP(primaryIP)
	}

	update = update.SetUpdateTime(time.Now())

	entity, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorDeviceNotFound("device not found")
		}
		r.log.Errorf("update device failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update device failed")
	}
	return entity, nil
}

func (r *DeviceRepo) Delete(ctx context.Context, id string, force bool) error {
	if !force {
		count, err := r.entClient.Client().Device.Query().
			Where(device.ID(id)).
			QueryAddresses().
			Count(ctx)
		if err != nil {
			r.log.Errorf("check device addresses failed: %s", err.Error())
			return ipamV1.ErrorInternalServerError("delete device failed")
		}
		if count > 0 {
			return ipamV1.ErrorDeviceHasAddresses("device has %d addresses", count)
		}
	}

	err := r.entClient.Client().Device.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorDeviceNotFound("device not found")
		}
		r.log.Errorf("delete device failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete device failed")
	}
	return nil
}

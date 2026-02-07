package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/vlan"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

type VlanRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewVlanRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *VlanRepo {
	return &VlanRepo{
		log:       ctx.NewLoggerHelper("ipam/vlan/repo"),
		entClient: entClient,
	}
}

func (r *VlanRepo) Create(ctx context.Context, tenantID uint32, vlanID int32, name string, opts ...func(*ent.VlanCreate)) (*ent.Vlan, error) {
	id := uuid.New().String()

	create := r.entClient.Client().Vlan.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetVlanID(vlanID).
		SetName(name).
		SetStatus(1).
		SetCreateTime(time.Now())

	for _, opt := range opts {
		opt(create)
	}

	entity, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ipamV1.ErrorVlanAlreadyExists("VLAN %d already exists", vlanID)
		}
		r.log.Errorf("create vlan failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create vlan failed")
	}
	return entity, nil
}

func (r *VlanRepo) GetByID(ctx context.Context, id string) (*ent.Vlan, error) {
	entity, err := r.entClient.Client().Vlan.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get vlan failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get vlan failed")
	}
	return entity, nil
}

func (r *VlanRepo) List(ctx context.Context, tenantID uint32, page, pageSize int, filters map[string]interface{}) ([]*ent.Vlan, int, error) {
	query := r.entClient.Client().Vlan.Query().Where(vlan.TenantID(tenantID))

	if locationID, ok := filters["location_id"].(string); ok && locationID != "" {
		query = query.Where(vlan.LocationID(locationID))
	}
	if status, ok := filters["status"].(int32); ok && status > 0 {
		query = query.Where(vlan.Status(status))
	}

	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count vlans failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list vlans failed")
	}

	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	entities, err := query.Order(ent.Asc(vlan.FieldVlanID)).All(ctx)
	if err != nil {
		r.log.Errorf("list vlans failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list vlans failed")
	}

	return entities, total, nil
}

func (r *VlanRepo) Update(ctx context.Context, id string, updates map[string]interface{}) (*ent.Vlan, error) {
	update := r.entClient.Client().Vlan.UpdateOneID(id)

	if name, ok := updates["name"].(string); ok {
		update = update.SetName(name)
	}
	if description, ok := updates["description"].(string); ok {
		update = update.SetDescription(description)
	}
	if domain, ok := updates["domain"].(string); ok {
		update = update.SetDomain(domain)
	}
	if status, ok := updates["status"].(int32); ok {
		update = update.SetStatus(status)
	}

	update = update.SetUpdateTime(time.Now())

	entity, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorVlanNotFound("vlan not found")
		}
		r.log.Errorf("update vlan failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update vlan failed")
	}
	return entity, nil
}

func (r *VlanRepo) Delete(ctx context.Context, id string, force bool) error {
	if !force {
		count, err := r.entClient.Client().Vlan.Query().
			Where(vlan.ID(id)).
			QuerySubnets().
			Count(ctx)
		if err != nil {
			r.log.Errorf("check vlan subnets failed: %s", err.Error())
			return ipamV1.ErrorInternalServerError("delete vlan failed")
		}
		if count > 0 {
			return ipamV1.ErrorVlanHasSubnets("vlan has %d subnets", count)
		}
	}

	err := r.entClient.Client().Vlan.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorVlanNotFound("vlan not found")
		}
		r.log.Errorf("delete vlan failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete vlan failed")
	}
	return nil
}

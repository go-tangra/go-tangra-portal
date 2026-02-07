package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/data/ent/location"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
)

type LocationRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewLocationRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *LocationRepo {
	return &LocationRepo{
		log:       ctx.NewLoggerHelper("ipam/location/repo"),
		entClient: entClient,
	}
}

func (r *LocationRepo) Create(ctx context.Context, tenantID uint32, name string, opts ...func(*ent.LocationCreate)) (*ent.Location, error) {
	id := uuid.New().String()

	create := r.entClient.Client().Location.Create().
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
			return nil, ipamV1.ErrorLocationAlreadyExists("location '%s' already exists", name)
		}
		r.log.Errorf("create location failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("create location failed")
	}
	return entity, nil
}

func (r *LocationRepo) GetByID(ctx context.Context, id string) (*ent.Location, error) {
	entity, err := r.entClient.Client().Location.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("get location failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get location failed")
	}
	return entity, nil
}

func (r *LocationRepo) List(ctx context.Context, tenantID uint32, page, pageSize int, filters map[string]interface{}) ([]*ent.Location, int, error) {
	query := r.entClient.Client().Location.Query().Where(location.TenantID(tenantID))

	if parentID, ok := filters["parent_id"].(string); ok && parentID != "" {
		query = query.Where(location.ParentID(parentID))
	}
	if locationType, ok := filters["location_type"].(int32); ok && locationType > 0 {
		query = query.Where(location.LocationType(locationType))
	}
	if status, ok := filters["status"].(int32); ok && status > 0 {
		query = query.Where(location.Status(status))
	}

	total, err := query.Clone().Count(ctx)
	if err != nil {
		r.log.Errorf("count locations failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list locations failed")
	}

	if page > 0 && pageSize > 0 {
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}

	entities, err := query.Order(ent.Asc(location.FieldName)).All(ctx)
	if err != nil {
		r.log.Errorf("list locations failed: %s", err.Error())
		return nil, 0, ipamV1.ErrorInternalServerError("list locations failed")
	}

	return entities, total, nil
}

func (r *LocationRepo) Update(ctx context.Context, id string, updates map[string]interface{}) (*ent.Location, error) {
	update := r.entClient.Client().Location.UpdateOneID(id)

	if name, ok := updates["name"].(string); ok {
		update = update.SetName(name)
	}
	if description, ok := updates["description"].(string); ok {
		update = update.SetDescription(description)
	}
	if status, ok := updates["status"].(int32); ok {
		update = update.SetStatus(status)
	}

	update = update.SetUpdateTime(time.Now())

	entity, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ipamV1.ErrorLocationNotFound("location not found")
		}
		r.log.Errorf("update location failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("update location failed")
	}
	return entity, nil
}

func (r *LocationRepo) Delete(ctx context.Context, id string, force bool) error {
	if !force {
		count, err := r.entClient.Client().Location.Query().
			Where(location.ID(id)).
			QueryChildren().
			Count(ctx)
		if err != nil {
			r.log.Errorf("check location children failed: %s", err.Error())
			return ipamV1.ErrorInternalServerError("delete location failed")
		}
		if count > 0 {
			return ipamV1.ErrorLocationHasChildren("location has %d children", count)
		}
	}

	err := r.entClient.Client().Location.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ipamV1.ErrorLocationNotFound("location not found")
		}
		r.log.Errorf("delete location failed: %s", err.Error())
		return ipamV1.ErrorInternalServerError("delete location failed")
	}
	return nil
}

func (r *LocationRepo) GetTree(ctx context.Context, tenantID uint32, rootID string) ([]*ent.Location, error) {
	query := r.entClient.Client().Location.Query().Where(location.TenantID(tenantID))

	// If rootID is specified, we need to get that location and all its descendants
	// For now, fetch all locations for the tenant to build the tree in the service layer
	// This allows the service to properly construct parent-child relationships

	entities, err := query.Order(ent.Asc(location.FieldName)).All(ctx)
	if err != nil {
		r.log.Errorf("get location tree failed: %s", err.Error())
		return nil, ipamV1.ErrorInternalServerError("get location tree failed")
	}

	// If rootID is specified, filter to only include the subtree starting from rootID
	if rootID != "" {
		// Build a set of IDs that belong to the subtree
		subtreeIDs := make(map[string]bool)
		subtreeIDs[rootID] = true

		// Keep iterating until no new children are found
		for {
			foundNew := false
			for _, e := range entities {
				if e.ParentID != "" && subtreeIDs[e.ParentID] && !subtreeIDs[e.ID] {
					subtreeIDs[e.ID] = true
					foundNew = true
				}
			}
			if !foundNew {
				break
			}
		}

		// Filter entities to only include those in the subtree
		var filtered []*ent.Location
		for _, e := range entities {
			if subtreeIDs[e.ID] {
				filtered = append(filtered, e)
			}
		}
		entities = filtered
	}

	return entities, nil
}

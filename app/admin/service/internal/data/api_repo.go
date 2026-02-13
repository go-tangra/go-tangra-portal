package data

import (
	"context"

	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	paginationV1 "github.com/tx7do/go-crud/api/gen/go/pagination/v1"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/api"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/predicate"

	"github.com/tx7do/go-utils/copierutil"
	"github.com/tx7do/go-utils/mapper"

	permissionV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/permission/service/v1"
)

type ApiRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper

	mapper         *mapper.CopierMapper[permissionV1.Api, ent.Api]
	scopeConverter *mapper.EnumTypeConverter[permissionV1.Api_Scope, api.Scope]

	repository *entCrud.Repository[
		ent.APIQuery, ent.APISelect,
		ent.APICreate, ent.APICreateBulk,
		ent.APIUpdate, ent.APIUpdateOne,
		ent.APIDelete,
		predicate.Api,
		permissionV1.Api, ent.Api,
	]
}

func NewApiRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *ApiRepo {
	repo := &ApiRepo{
		log:       ctx.NewLoggerHelper("api/repo/admin-service"),
		entClient: entClient,
		mapper:    mapper.NewCopierMapper[permissionV1.Api, ent.Api](),
		scopeConverter: mapper.NewEnumTypeConverter[permissionV1.Api_Scope, api.Scope](
			permissionV1.Api_Scope_name, permissionV1.Api_Scope_value,
		),
	}

	repo.init()

	return repo
}

func (r *ApiRepo) init() {
	r.repository = entCrud.NewRepository[
		ent.APIQuery, ent.APISelect,
		ent.APICreate, ent.APICreateBulk,
		ent.APIUpdate, ent.APIUpdateOne,
		ent.APIDelete,
		predicate.Api,
		permissionV1.Api, ent.Api,
	](r.mapper)

	r.mapper.AppendConverters(copierutil.NewTimeStringConverterPair())
	r.mapper.AppendConverters(copierutil.NewTimeTimestamppbConverterPair())

	r.mapper.AppendConverters(r.scopeConverter.NewConverterPair())
}

func (r *ApiRepo) Count(ctx context.Context, whereCond []func(s *sql.Selector)) (int, error) {
	builder := r.entClient.Client().Api.Query()
	if len(whereCond) != 0 {
		builder.Modify(whereCond...)
	}

	count, err := builder.Count(ctx)
	if err != nil {
		r.log.Errorf("query count failed: %s", err.Error())
		return 0, permissionV1.ErrorInternalServerError("query count failed")
	}

	return count, nil
}

func (r *ApiRepo) List(ctx context.Context, req *paginationV1.PagingRequest) (*permissionV1.ListApiResponse, error) {
	if req == nil {
		return nil, permissionV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().Api.Query()

	ret, err := r.repository.ListWithPaging(ctx, builder, builder.Clone(), req)
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return &permissionV1.ListApiResponse{Total: 0, Items: nil}, nil
	}

	return &permissionV1.ListApiResponse{
		Total: ret.Total,
		Items: ret.Items,
	}, nil
}

func (r *ApiRepo) IsExist(ctx context.Context, id uint32) (bool, error) {
	exist, err := r.entClient.Client().Api.Query().
		Where(api.IDEQ(id)).
		Exist(ctx)
	if err != nil {
		r.log.Errorf("query exist failed: %s", err.Error())
		return false, permissionV1.ErrorInternalServerError("query exist failed")
	}
	return exist, nil
}

func (r *ApiRepo) Get(ctx context.Context, req *permissionV1.GetApiRequest) (*permissionV1.Api, error) {
	if req == nil {
		return nil, permissionV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().Api.Query()

	var whereCond []func(s *sql.Selector)
	switch req.QueryBy.(type) {
	default:
	case *permissionV1.GetApiRequest_Id:
		whereCond = append(whereCond, api.IDEQ(req.GetId()))
	}

	dto, err := r.repository.Get(ctx, builder, req.GetViewMask(), whereCond...)
	if err != nil {
		return nil, err
	}

	return dto, err
}

// GetApiByEndpoint 根据路径和方法获取API资源
func (r *ApiRepo) GetApiByEndpoint(ctx context.Context, path, method string) (*permissionV1.Api, error) {
	if path == "" || method == "" {
		return nil, permissionV1.ErrorBadRequest("invalid parameter")
	}

	entity, err := r.entClient.Client().Api.Query().
		Where(
			api.PathEQ(path),
			api.MethodEQ(method),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, permissionV1.ErrorNotFound("api not found")
		}

		r.log.Errorf("query one data failed: %s", err.Error())

		return nil, permissionV1.ErrorInternalServerError("query data failed")
	}

	return r.mapper.ToDTO(entity), nil
}

// GetApiByIDs 根据ID列表获取API资源
func (r *ApiRepo) GetApiByIDs(ctx context.Context, ids []uint32) ([]*permissionV1.Api, error) {
	if len(ids) == 0 {
		return nil, permissionV1.ErrorBadRequest("invalid parameter")
	}

	entities, err := r.entClient.Client().Api.Query().
		Where(
			api.IDIn(ids...),
		).
		All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, permissionV1.ErrorNotFound("api not found")
		}

		r.log.Errorf("query one data failed: %s", err.Error())

		return nil, permissionV1.ErrorInternalServerError("query data failed")
	}

	dtos := make([]*permissionV1.Api, 0, len(entities))
	for _, entity := range entities {
		dto := r.mapper.ToDTO(entity)
		dtos = append(dtos, dto)
	}

	return dtos, nil
}

func (r *ApiRepo) Create(ctx context.Context, req *permissionV1.CreateApiRequest) error {
	if req == nil || req.Data == nil {
		return permissionV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.newApiCreate(req.Data)

	if err := builder.Exec(ctx); err != nil {
		r.log.Errorf("insert api failed: %s", err.Error())
		return permissionV1.ErrorInternalServerError("insert api failed")
	}

	return nil
}

func (r *ApiRepo) newApiCreate(api *permissionV1.Api) *ent.APICreate {
	builder := r.entClient.Client().Api.Create().
		SetNillableDescription(api.Description).
		SetNillableModule(api.Module).
		SetNillableModuleDescription(api.ModuleDescription).
		SetNillableOperation(api.Operation).
		SetNillablePath(api.Path).
		SetNillableMethod(api.Method).
		SetNillableScope(r.scopeConverter.ToEntity(api.Scope)).
		SetNillableCreatedBy(api.CreatedBy).
		SetCreatedAt(time.Now())

	if api.Id != nil {
		builder.SetID(api.GetId())
	}

	return builder
}

func (r *ApiRepo) BatchCreate(ctx context.Context, apis []*permissionV1.Api) error {
	if len(apis) == 0 {
		return nil
	}

	bulk := make([]*ent.APICreate, 0, len(apis))
	for _, dto := range apis {
		builder := r.newApiCreate(dto)
		bulk = append(bulk, builder)
	}

	bulkBuilder := r.entClient.Client().Api.CreateBulk(bulk...)

	if err := bulkBuilder.Exec(ctx); err != nil {
		r.log.Errorf("batch insert apis failed: %s", err.Error())
		return permissionV1.ErrorInternalServerError("batch insert apis failed")
	}

	return nil
}

func (r *ApiRepo) Update(ctx context.Context, req *permissionV1.UpdateApiRequest) error {
	if req == nil || req.Data == nil {
		return permissionV1.ErrorBadRequest("invalid parameter")
	}

	// 如果不存在则创建
	if req.GetAllowMissing() {
		exist, err := r.IsExist(ctx, req.GetId())
		if err != nil {
			return err
		}
		if !exist {
			createReq := &permissionV1.CreateApiRequest{Data: req.Data}
			createReq.Data.CreatedBy = createReq.Data.UpdatedBy
			createReq.Data.UpdatedBy = nil
			return r.Create(ctx, createReq)
		}
	}

	builder := r.entClient.Client().Api.Update()
	err := r.repository.UpdateX(ctx, builder, req.Data, req.GetUpdateMask(),
		func(dto *permissionV1.Api) {
			builder.
				SetNillableDescription(req.Data.Description).
				SetNillableModule(req.Data.Module).
				SetNillableModuleDescription(req.Data.ModuleDescription).
				SetNillableOperation(req.Data.Operation).
				SetNillablePath(req.Data.Path).
				SetNillableMethod(req.Data.Method).
				SetNillableScope(r.scopeConverter.ToEntity(req.Data.Scope)).
				SetNillableUpdatedBy(req.Data.UpdatedBy).
				SetUpdatedAt(time.Now())
		},
		func(s *sql.Selector) {
			s.Where(sql.EQ(api.FieldID, req.GetId()))
		},
	)

	return err
}

func (r *ApiRepo) Delete(ctx context.Context, req *permissionV1.DeleteApiRequest) error {
	if req == nil {
		return permissionV1.ErrorBadRequest("invalid parameter")
	}

	builder := r.entClient.Client().Api.Delete()

	_, err := r.repository.Delete(ctx, builder, func(s *sql.Selector) {
		s.Where(sql.EQ(api.FieldID, req.GetId()))
	})
	if err != nil {
		r.log.Errorf("delete api failed: %s", err.Error())
		return permissionV1.ErrorInternalServerError("delete api failed")
	}

	return nil
}

// Truncate 清空表数据
func (r *ApiRepo) Truncate(ctx context.Context) error {
	if _, err := r.entClient.Client().Api.Delete().Exec(ctx); err != nil {
		r.log.Errorf("failed to truncate apis table: %s", err.Error())
		return permissionV1.ErrorInternalServerError("truncate failed")
	}
	return nil
}

// GetAPIByPathAndMethod retrieves an API by its path and method.
func (r *ApiRepo) GetAPIByPathAndMethod(ctx context.Context, path, method string) (*ent.Api, error) {
	entity, err := r.entClient.Client().Api.Query().
		Where(
			api.PathEQ(path),
			api.MethodEQ(method),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil // API not found is not an error
		}
		r.log.Errorf("query API by path and method failed: %s", err.Error())
		return nil, permissionV1.ErrorInternalServerError("query API by path and method failed")
	}
	return entity, nil
}

// FindAPIsByPathPrefix finds all APIs whose path starts with the given prefix.
func (r *ApiRepo) FindAPIsByPathPrefix(ctx context.Context, prefix string) ([]*ent.Api, error) {
	entities, err := r.entClient.Client().Api.Query().
		Where(api.PathHasPrefix(prefix)).
		All(ctx)
	if err != nil {
		r.log.Errorf("query APIs by path prefix failed: %s", err.Error())
		return nil, permissionV1.ErrorInternalServerError("query APIs by path prefix failed")
	}
	return entities, nil
}

// DeleteByID deletes an API by its database ID.
func (r *ApiRepo) DeleteByID(ctx context.Context, id uint32) error {
	err := r.entClient.Client().Api.DeleteOneID(id).Exec(ctx)
	if err != nil {
		r.log.Errorf("delete API by id failed: %s", err.Error())
		return permissionV1.ErrorInternalServerError("delete API by id failed")
	}
	return nil
}

// UpsertAPI creates or updates an API by module, path, method, and scope.
// The unique constraint is on (module, path, method, scope).
func (r *ApiRepo) UpsertAPI(ctx context.Context, data *permissionV1.Api) (*ent.Api, error) {
	if data == nil || data.Path == nil || data.Method == nil {
		return nil, permissionV1.ErrorBadRequest("path and method are required")
	}

	// Determine the scope to use (default to ADMIN if not specified)
	scope := api.ScopeAdmin
	if data.Scope != nil {
		if converted := r.scopeConverter.ToEntity(data.Scope); converted != nil {
			scope = *converted
		}
	}

	// First try to find existing by full unique key (module, path, method, scope)
	existing, err := r.findByUniqueKey(ctx, data.GetModule(), data.GetPath(), data.GetMethod(), scope)
	if err != nil {
		r.log.Warnf("lookup API (module=%s, path=%s, method=%s) failed: %s", data.GetModule(), data.GetPath(), data.GetMethod(), err.Error())
		// Continue to try creating - the error might be transient
	}

	if existing != nil {
		// Update existing
		updated, err := r.entClient.Client().Api.UpdateOneID(existing.ID).
			SetNillableDescription(data.Description).
			SetNillableModuleDescription(data.ModuleDescription).
			SetNillableOperation(data.Operation).
			SetUpdatedAt(time.Now()).
			Save(ctx)
		if err != nil {
			r.log.Errorf("update API (id=%d) failed: %s", existing.ID, err.Error())
			return nil, permissionV1.ErrorInternalServerError("update API failed")
		}
			return updated, nil
	}

	// Create new with OnConflict for atomic upsert
	id, err := r.entClient.Client().Api.Create().
		SetNillableDescription(data.Description).
		SetNillableModule(data.Module).
		SetNillableModuleDescription(data.ModuleDescription).
		SetNillableOperation(data.Operation).
		SetNillablePath(data.Path).
		SetNillableMethod(data.Method).
		SetScope(scope).
		SetCreatedAt(time.Now()).
		OnConflictColumns(api.FieldModule, api.FieldPath, api.FieldMethod, api.FieldScope).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		// If upsert fails (e.g., primary key sequence out of sync), try to find and update
		r.log.Warnf("upsert API failed, trying fallback update: %s", err.Error())

		// Retry lookup - maybe it was a race condition
		existing, lookupErr := r.findByUniqueKey(ctx, data.GetModule(), data.GetPath(), data.GetMethod(), scope)
		if lookupErr != nil {
			r.log.Errorf("fallback lookup failed: %s", lookupErr.Error())
			return nil, permissionV1.ErrorInternalServerError("upsert API failed")
		}
		if existing != nil {
			// Found it - update
			updated, updateErr := r.entClient.Client().Api.UpdateOneID(existing.ID).
				SetNillableDescription(data.Description).
				SetNillableModuleDescription(data.ModuleDescription).
				SetNillableOperation(data.Operation).
				SetUpdatedAt(time.Now()).
				Save(ctx)
			if updateErr != nil {
				r.log.Errorf("fallback update API (id=%d) failed: %s", existing.ID, updateErr.Error())
				return nil, permissionV1.ErrorInternalServerError("update API failed")
			}
			r.log.Infof("fallback updated API (id=%d, module=%s, path=%s, method=%s)", updated.ID, data.GetModule(), data.GetPath(), data.GetMethod())
			return updated, nil
		}

		r.log.Errorf("upsert API failed and no existing record found: module=%s, path=%s, method=%s", data.GetModule(), data.GetPath(), data.GetMethod())
		return nil, permissionV1.ErrorInternalServerError("upsert API failed")
	}

	// Fetch the created/updated record
	result, err := r.entClient.Client().Api.Get(ctx, id)
	if err != nil {
		r.log.Errorf("fetch API after upsert (id=%d) failed: %s", id, err.Error())
		return nil, permissionV1.ErrorInternalServerError("fetch API failed")
	}
	return result, nil
}

// findByUniqueKey finds an API by its full unique key (module, path, method, scope).
func (r *ApiRepo) findByUniqueKey(ctx context.Context, module, path, method string, scope api.Scope) (*ent.Api, error) {
	entity, err := r.entClient.Client().Api.Query().
		Where(
			api.ModuleEQ(module),
			api.PathEQ(path),
			api.MethodEQ(method),
			api.ScopeEQ(scope),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil // Not found is not an error
		}
		return nil, err
	}
	return entity, nil
}

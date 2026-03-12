package data

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"
)

// StatisticsRepo provides methods for collecting portal statistics
// used to seed Prometheus metrics at startup.
type StatisticsRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewStatisticsRepo creates a new StatisticsRepo.
func NewStatisticsRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *StatisticsRepo {
	return &StatisticsRepo{
		entClient: entClient,
		log:       ctx.NewLoggerHelper("portal/statistics/repo"),
	}
}

// GetGlobalUserCount returns the total number of users across all tenants.
func (r *StatisticsRepo) GetGlobalUserCount(ctx context.Context) (int64, error) {
	count, err := r.entClient.Client().User.Query().Count(ctx)
	if err != nil {
		r.log.Errorf("get global user count failed: %s", err.Error())
		return 0, fmt.Errorf("get user statistics failed: %w", err)
	}
	return int64(count), nil
}

// GetGlobalRoleCount returns the total number of roles across all tenants.
func (r *StatisticsRepo) GetGlobalRoleCount(ctx context.Context) (int64, error) {
	count, err := r.entClient.Client().Role.Query().Count(ctx)
	if err != nil {
		r.log.Errorf("get global role count failed: %s", err.Error())
		return 0, fmt.Errorf("get role statistics failed: %w", err)
	}
	return int64(count), nil
}

// GetGlobalTenantCount returns the total number of tenants.
func (r *StatisticsRepo) GetGlobalTenantCount(ctx context.Context) (int64, error) {
	count, err := r.entClient.Client().Tenant.Query().Count(ctx)
	if err != nil {
		r.log.Errorf("get global tenant count failed: %s", err.Error())
		return 0, fmt.Errorf("get tenant statistics failed: %w", err)
	}
	return int64(count), nil
}

// GetGlobalMenuCount returns the total number of menus across all tenants.
func (r *StatisticsRepo) GetGlobalMenuCount(ctx context.Context) (int64, error) {
	count, err := r.entClient.Client().Menu.Query().Count(ctx)
	if err != nil {
		r.log.Errorf("get global menu count failed: %s", err.Error())
		return 0, fmt.Errorf("get menu statistics failed: %w", err)
	}
	return int64(count), nil
}

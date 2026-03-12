package metrics

import (
	"context"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
)

// Seed loads initial gauge values from the database.
// Called once at startup so Prometheus has accurate values from the start.
func (c *Collector) Seed(ctx context.Context, statsRepo *data.StatisticsRepo) {
	c.log.Info("Seeding Prometheus metrics from database...")

	userCount, err := statsRepo.GetGlobalUserCount(ctx)
	if err != nil {
		c.log.Errorf("Failed to seed user stats: %v", err)
	} else {
		c.UsersTotal.Set(float64(userCount))
	}

	roleCount, err := statsRepo.GetGlobalRoleCount(ctx)
	if err != nil {
		c.log.Errorf("Failed to seed role stats: %v", err)
	} else {
		c.RolesTotal.Set(float64(roleCount))
	}

	tenantCount, err := statsRepo.GetGlobalTenantCount(ctx)
	if err != nil {
		c.log.Errorf("Failed to seed tenant stats: %v", err)
	} else {
		c.TenantsTotal.Set(float64(tenantCount))
	}

	menuCount, err := statsRepo.GetGlobalMenuCount(ctx)
	if err != nil {
		c.log.Errorf("Failed to seed menu stats: %v", err)
	} else {
		c.MenusTotal.Set(float64(menuCount))
	}

	c.log.Info("Prometheus metrics seeded successfully")
}

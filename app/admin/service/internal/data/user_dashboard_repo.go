package data

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/schema"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/userdashboard"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
)

// UserDashboardRepo handles database operations for user dashboard configurations.
type UserDashboardRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

// NewUserDashboardRepo creates a new UserDashboardRepo.
func NewUserDashboardRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *UserDashboardRepo {
	return &UserDashboardRepo{
		log:       ctx.NewLoggerHelper("user-dashboard/repo/admin-service"),
		entClient: entClient,
	}
}

// GetByUser retrieves the dashboard for a specific user and tenant.
func (r *UserDashboardRepo) GetByUser(ctx context.Context, userID, tenantID uint32) (*ent.UserDashboard, error) {
	entity, err := r.entClient.Client().UserDashboard.Query().
		Where(
			userdashboard.UserIDEQ(userID),
			userdashboard.TenantIDEQ(tenantID),
			userdashboard.IsDefaultEQ(true),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		r.log.Errorf("query user dashboard failed: %s", err.Error())
		return nil, adminV1.ErrorInternalServerError("query user dashboard failed")
	}
	return entity, nil
}

// Upsert creates or updates a user's dashboard.
func (r *UserDashboardRepo) Upsert(ctx context.Context, userID, tenantID uint32, name string, widgets []schema.DashboardWidgetConfig) (*ent.UserDashboard, error) {
	// Try to find existing
	existing, err := r.GetByUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		// Update existing
		entity, err := r.entClient.Client().UserDashboard.UpdateOneID(existing.ID).
			SetName(name).
			SetWidgets(widgets).
			Save(ctx)
		if err != nil {
			r.log.Errorf("update user dashboard failed: %s", err.Error())
			return nil, adminV1.ErrorInternalServerError("update user dashboard failed")
		}
		return entity, nil
	}

	// Create new
	entity, err := r.entClient.Client().UserDashboard.Create().
		SetUserID(userID).
		SetTenantID(tenantID).
		SetName(name).
		SetWidgets(widgets).
		SetIsDefault(true).
		Save(ctx)
	if err != nil {
		r.log.Errorf("create user dashboard failed: %s", err.Error())
		return nil, adminV1.ErrorInternalServerError("create user dashboard failed")
	}
	return entity, nil
}

// Delete deletes a user's dashboard (for reset).
func (r *UserDashboardRepo) Delete(ctx context.Context, userID, tenantID uint32) error {
	_, err := r.entClient.Client().UserDashboard.Delete().
		Where(
			userdashboard.UserIDEQ(userID),
			userdashboard.TenantIDEQ(tenantID),
		).
		Exec(ctx)
	if err != nil {
		r.log.Errorf("delete user dashboard failed: %s", err.Error())
		return adminV1.ErrorInternalServerError("delete user dashboard failed")
	}
	return nil
}

package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
	deployerV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/deployer/service/v1"
	ipamV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/ipam/service/v1"
	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	paperlessV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/paperless/service/v1"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/role"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/tenant"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/user"
)

// PlatformStatisticsService implements the HTTP gateway for platform statistics
type PlatformStatisticsService struct {
	adminV1.PlatformStatisticsServiceHTTPServer

	log              *log.Helper
	lcmClients       *data.LcmClients
	deployerClients  *data.DeployerClients
	paperlessClients *data.PaperlessClients
	ipamClients      *data.IpamClients
	entClient        *entCrud.EntClient[*ent.Client]
}

// NewPlatformStatisticsService creates a new PlatformStatisticsService
func NewPlatformStatisticsService(
	ctx *bootstrap.Context,
	lcmClients *data.LcmClients,
	deployerClients *data.DeployerClients,
	paperlessClients *data.PaperlessClients,
	ipamClients *data.IpamClients,
	entClient *entCrud.EntClient[*ent.Client],
) *PlatformStatisticsService {
	return &PlatformStatisticsService{
		log:              ctx.NewLoggerHelper("statistics/gateway/admin-service"),
		lcmClients:       lcmClients,
		deployerClients:  deployerClients,
		paperlessClients: paperlessClients,
		ipamClients:      ipamClients,
		entClient:        entClient,
	}
}

// GetPlatformStatistics returns comprehensive statistics about the platform
func (s *PlatformStatisticsService) GetPlatformStatistics(ctx context.Context, req *adminV1.GetPlatformStatisticsRequest) (*adminV1.GetPlatformStatisticsResponse, error) {
	s.log.Info("GetPlatformStatistics called")

	response := &adminV1.GetPlatformStatisticsResponse{
		GeneratedAt: timestamppb.Now(),
	}

	// Get admin statistics
	adminStats, err := s.getAdminStatistics(ctx)
	if err != nil {
		s.log.Errorf("Failed to get admin statistics: %v", err)
		// Continue even if admin stats fail
	} else {
		response.Admin = adminStats
	}

	// Get LCM statistics if available
	if s.lcmClients != nil && s.lcmClients.StatisticsService != nil {
		lcmReq := &lcmV1.GetStatisticsRequest{}
		if req.ExpireSoonDays != nil {
			lcmReq.ExpireSoonDays = req.ExpireSoonDays
		}
		if req.RecentErrorsLimit != nil {
			lcmReq.RecentErrorsLimit = req.RecentErrorsLimit
		}

		lcmStats, err := s.lcmClients.StatisticsService.GetStatistics(ctx, lcmReq)
		if err != nil {
			s.log.Errorf("Failed to get LCM statistics: %v", err)
			// Continue even if LCM stats fail
		} else {
			response.Lcm = lcmStats
		}
	} else {
		s.log.Warn("LCM service is not available for statistics")
	}

	// Get Deployer statistics if available
	if s.deployerClients != nil && s.deployerClients.StatisticsService != nil {
		deployerReq := &deployerV1.GetStatisticsRequest{}
		if req.RecentErrorsLimit != nil {
			deployerReq.RecentErrorsLimit = req.RecentErrorsLimit
		}

		deployerStats, err := s.deployerClients.StatisticsService.GetStatistics(ctx, deployerReq)
		if err != nil {
			s.log.Errorf("Failed to get Deployer statistics: %v", err)
			// Continue even if Deployer stats fail
		} else {
			response.Deployer = deployerStats
		}
	} else {
		s.log.Warn("Deployer service is not available for statistics")
	}

	// Get Paperless statistics if available
	if s.paperlessClients != nil && s.paperlessClients.StatisticsService != nil {
		paperlessReq := &paperlessV1.GetStatisticsRequest{}

		paperlessStats, err := s.paperlessClients.StatisticsService.GetStatistics(ctx, paperlessReq)
		if err != nil {
			s.log.Errorf("Failed to get Paperless statistics: %v", err)
		} else {
			response.Paperless = paperlessStats
		}
	} else {
		s.log.Warn("Paperless service is not available for statistics")
	}

	// Get IPAM statistics if available
	if s.ipamClients != nil && s.ipamClients.SystemService != nil {
		ipamReq := &ipamV1.GetStatsRequest{}

		ipamStats, err := s.ipamClients.SystemService.GetStats(ctx, ipamReq)
		if err != nil {
			s.log.Errorf("Failed to get IPAM statistics: %v", err)
		} else {
			response.Ipam = ipamStats
		}
	} else {
		s.log.Warn("IPAM service is not available for statistics")
	}

	return response, nil
}

// getAdminStatistics collects statistics from admin service entities
func (s *PlatformStatisticsService) getAdminStatistics(ctx context.Context) (*adminV1.AdminStatistics, error) {
	adminStats := &adminV1.AdminStatistics{}

	// Get user statistics
	userStats, err := s.getUserStatistics(ctx)
	if err != nil {
		s.log.Errorf("Failed to get user statistics: %v", err)
	} else {
		adminStats.Users = userStats
	}

	// Get tenant statistics
	tenantStats, err := s.getTenantStatistics(ctx)
	if err != nil {
		s.log.Errorf("Failed to get tenant statistics: %v", err)
	} else {
		adminStats.Tenants = tenantStats
	}

	// Get role statistics
	roleStats, err := s.getRoleStatistics(ctx)
	if err != nil {
		s.log.Errorf("Failed to get role statistics: %v", err)
	} else {
		adminStats.Roles = roleStats
	}

	return adminStats, nil
}

// getUserStatistics collects user statistics
func (s *PlatformStatisticsService) getUserStatistics(ctx context.Context) (*adminV1.UserStatistics, error) {
	client := s.entClient.Client()
	stats := &adminV1.UserStatistics{
		ByStatus: make(map[string]int64),
	}

	// Total count
	total, err := client.User.Query().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = int64(total)

	// Active count (NORMAL status)
	active, err := client.User.Query().Where(user.StatusEQ(user.StatusNormal)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ActiveCount = int64(active)
	stats.ByStatus["normal"] = int64(active)

	// Inactive count (OFF status equivalent - DISABLED, PENDING, EXPIRED, CLOSED)
	inactive, err := client.User.Query().Where(
		user.StatusIn(user.StatusDisabled, user.StatusPending, user.StatusExpired, user.StatusClosed),
	).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.InactiveCount = int64(inactive)

	// Locked count
	locked, err := client.User.Query().Where(user.StatusEQ(user.StatusLocked)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.LockedCount = int64(locked)
	stats.ByStatus["locked"] = int64(locked)

	// Disabled count
	disabled, err := client.User.Query().Where(user.StatusEQ(user.StatusDisabled)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.DisabledCount = int64(disabled)
	stats.ByStatus["disabled"] = int64(disabled)

	// Add other statuses to map
	pending, _ := client.User.Query().Where(user.StatusEQ(user.StatusPending)).Count(ctx)
	stats.ByStatus["pending"] = int64(pending)

	expired, _ := client.User.Query().Where(user.StatusEQ(user.StatusExpired)).Count(ctx)
	stats.ByStatus["expired"] = int64(expired)

	closed, _ := client.User.Query().Where(user.StatusEQ(user.StatusClosed)).Count(ctx)
	stats.ByStatus["closed"] = int64(closed)

	return stats, nil
}

// getTenantStatistics collects tenant statistics
func (s *PlatformStatisticsService) getTenantStatistics(ctx context.Context) (*adminV1.TenantStatistics, error) {
	client := s.entClient.Client()
	stats := &adminV1.TenantStatistics{
		ByStatus: make(map[string]int64),
		ByType:   make(map[string]int64),
	}

	// Total count
	total, err := client.Tenant.Query().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = int64(total)

	// Active count (ON status)
	active, err := client.Tenant.Query().Where(tenant.StatusEQ(tenant.StatusOn)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ActiveCount = int64(active)
	stats.ByStatus["on"] = int64(active)

	// Inactive count (OFF status)
	inactive, err := client.Tenant.Query().Where(tenant.StatusEQ(tenant.StatusOff)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.InactiveCount = int64(inactive)
	stats.ByStatus["off"] = int64(inactive)

	// Suspended count (FREEZE + EXPIRED)
	frozen, err := client.Tenant.Query().Where(tenant.StatusEQ(tenant.StatusFreeze)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ByStatus["freeze"] = int64(frozen)

	expired, err := client.Tenant.Query().Where(tenant.StatusEQ(tenant.StatusExpired)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ByStatus["expired"] = int64(expired)

	stats.SuspendedCount = int64(frozen) + int64(expired)

	// Count by type
	trial, _ := client.Tenant.Query().Where(tenant.TypeEQ(tenant.TypeTrial)).Count(ctx)
	stats.ByType["trial"] = int64(trial)

	paid, _ := client.Tenant.Query().Where(tenant.TypeEQ(tenant.TypePaid)).Count(ctx)
	stats.ByType["paid"] = int64(paid)

	internal, _ := client.Tenant.Query().Where(tenant.TypeEQ(tenant.TypeInternal)).Count(ctx)
	stats.ByType["internal"] = int64(internal)

	partner, _ := client.Tenant.Query().Where(tenant.TypeEQ(tenant.TypePartner)).Count(ctx)
	stats.ByType["partner"] = int64(partner)

	custom, _ := client.Tenant.Query().Where(tenant.TypeEQ(tenant.TypeCustom)).Count(ctx)
	stats.ByType["custom"] = int64(custom)

	return stats, nil
}

// getRoleStatistics collects role statistics
func (s *PlatformStatisticsService) getRoleStatistics(ctx context.Context) (*adminV1.RoleStatistics, error) {
	client := s.entClient.Client()
	stats := &adminV1.RoleStatistics{}

	// Total count
	total, err := client.Role.Query().Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = int64(total)

	// Active count (ON status)
	active, err := client.Role.Query().Where(role.StatusEQ(role.StatusOn)).Count(ctx)
	if err != nil {
		return nil, err
	}
	stats.ActiveCount = int64(active)

	return stats, nil
}

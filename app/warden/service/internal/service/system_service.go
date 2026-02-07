package service

import (
	"context"
	"runtime"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/go-tangra/go-tangra-portal/app/warden/service/pkg/vault"

	wardenV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/warden/service/v1"
)

var (
	// Version is set at build time
	Version = "dev"
	// BuildTime is set at build time
	BuildTime = "unknown"
	// GitCommit is set at build time
	GitCommit = "unknown"
)

type SystemService struct {
	wardenV1.UnimplementedWardenSystemServiceServer

	log         *log.Helper
	vaultClient *vault.Client
}

func NewSystemService(
	ctx *bootstrap.Context,
	vaultClient *vault.Client,
) *SystemService {
	return &SystemService{
		log:         ctx.NewLoggerHelper("warden/service/system"),
		vaultClient: vaultClient,
	}
}

// Health returns the health status of the service
func (s *SystemService) Health(ctx context.Context, _ *emptypb.Empty) (*wardenV1.HealthResponse, error) {
	components := make(map[string]*wardenV1.ComponentHealth)

	// Check Vault health
	vaultHealth := &wardenV1.ComponentHealth{
		Status:  wardenV1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Message: "connected",
	}

	if s.vaultClient != nil {
		health, err := s.vaultClient.Health(ctx)
		if err != nil {
			vaultHealth.Status = wardenV1.HealthStatus_HEALTH_STATUS_UNHEALTHY
			vaultHealth.Message = err.Error()
		} else if health.Sealed {
			vaultHealth.Status = wardenV1.HealthStatus_HEALTH_STATUS_DEGRADED
			vaultHealth.Message = "Vault is sealed"
		}
	} else {
		vaultHealth.Status = wardenV1.HealthStatus_HEALTH_STATUS_UNHEALTHY
		vaultHealth.Message = "Vault client not configured"
	}
	components["vault"] = vaultHealth

	// Determine overall status
	overallStatus := wardenV1.HealthStatus_HEALTH_STATUS_HEALTHY
	overallMessage := "all systems operational"

	for _, component := range components {
		if component.Status == wardenV1.HealthStatus_HEALTH_STATUS_UNHEALTHY {
			overallStatus = wardenV1.HealthStatus_HEALTH_STATUS_UNHEALTHY
			overallMessage = "one or more components are unhealthy"
			break
		}
		if component.Status == wardenV1.HealthStatus_HEALTH_STATUS_DEGRADED {
			overallStatus = wardenV1.HealthStatus_HEALTH_STATUS_DEGRADED
			overallMessage = "one or more components are degraded"
		}
	}

	return &wardenV1.HealthResponse{
		Status:     overallStatus,
		Message:    overallMessage,
		Components: components,
	}, nil
}

// GetInfo returns service information
func (s *SystemService) GetInfo(ctx context.Context, _ *emptypb.Empty) (*wardenV1.GetInfoResponse, error) {
	return &wardenV1.GetInfoResponse{
		Version:   Version,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
		GitCommit: GitCommit,
	}, nil
}

// CheckVault checks Vault connectivity
func (s *SystemService) CheckVault(ctx context.Context, _ *emptypb.Empty) (*wardenV1.CheckVaultResponse, error) {
	if s.vaultClient == nil {
		return &wardenV1.CheckVaultResponse{
			Connected:    false,
			VaultVersion: "",
			Sealed:       true,
			Message:      "Vault client not configured",
		}, nil
	}

	health, err := s.vaultClient.Health(ctx)
	if err != nil {
		return &wardenV1.CheckVaultResponse{
			Connected:    false,
			VaultVersion: "",
			Sealed:       true,
			Message:      err.Error(),
		}, nil
	}

	return &wardenV1.CheckVaultResponse{
		Connected:    true,
		VaultVersion: health.Version,
		Sealed:       health.Sealed,
		Message:      "connection successful",
	}, nil
}

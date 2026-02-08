package main

import (
	"context"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	conf "github.com/tx7do/kratos-bootstrap/api/gen/go/conf/v1"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-portal/app/ipam/service/cmd/server/assets"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/registration"
	"github.com/go-tangra/go-tangra-portal/app/ipam/service/internal/service"
	pkgService "github.com/go-tangra/go-tangra-portal/pkg/service"
)

var (
	// Module info
	moduleID    = "ipam"
	moduleName  = "IPAM"
	version     = "1.0.0"
	description = "IP Address Management service for managing subnets, IP addresses, VLANs, devices, and locations"
)

// Global references for cleanup
var globalScanExecutor *service.ScanExecutor
var globalRegClient *registration.Client

func newApp(
	ctx *bootstrap.Context,
	gs *grpc.Server,
	scanExecutor *service.ScanExecutor,
) *kratos.App {
	// Start the scan executor and store reference for cleanup
	globalScanExecutor = scanExecutor
	if scanExecutor != nil {
		if err := scanExecutor.Start(); err != nil {
			log.Warnf("Failed to start scan executor: %v", err)
		}
	}

	// Get admin endpoint from environment
	adminEndpoint := getEnvOrDefault("ADMIN_GRPC_ENDPOINT", "")

	// Get gRPC advertise address for registration
	// GRPC_ADVERTISE_ADDR should be set to the address reachable by admin service (e.g., "ipam-service:9400" in Docker)
	// Falls back to bind address from config for local development
	grpcAddr := getEnvOrDefault("GRPC_ADVERTISE_ADDR", "")
	if grpcAddr == "" {
		grpcAddr = "0.0.0.0:9400" // default
		cfg := ctx.GetConfig()
		if cfg.Server != nil && cfg.Server.Grpc != nil && cfg.Server.Grpc.Addr != "" {
			grpcAddr = cfg.Server.Grpc.Addr
		}
	}

	logger := ctx.GetLogger()
	logHelper := log.NewHelper(logger)

	// Only register if admin endpoint is configured
	if adminEndpoint != "" {
		logHelper.Infof("Will register with admin gateway at: %s", adminEndpoint)

		// Start registration in background after a delay
		go func() {
			// Wait for gRPC server to be ready
			time.Sleep(3 * time.Second)

			regConfig := &registration.Config{
				ModuleID:          moduleID,
				ModuleName:        moduleName,
				Version:           version,
				Description:       description,
				GRPCEndpoint:      grpcAddr,
				AdminEndpoint:     adminEndpoint,
				OpenapiSpec:       assets.OpenApiData,
				ProtoDescriptor:   nil,
				MenusYaml:         assets.MenusData,
				HeartbeatInterval: 30 * time.Second,
				RetryInterval:     5 * time.Second,
				MaxRetries:        60, // Allow ~5 minutes for admin-service to be ready
			}

			regClient, err := registration.NewClient(logger, regConfig)
			if err != nil {
				logHelper.Warnf("Failed to create registration client: %v", err)
				return
			}
			globalRegClient = regClient

			// Register with admin gateway
			regCtx := context.Background()
			if err := regClient.Register(regCtx); err != nil {
				logHelper.Errorf("Failed to register with admin gateway: %v", err)
				return
			}

			// Start heartbeat
			go regClient.StartHeartbeat(regCtx)
		}()
	} else {
		logHelper.Info("ADMIN_GRPC_ENDPOINT not set, skipping module registration")
	}

	return bootstrap.NewApp(ctx, gs)
}

// stopRegistration unregisters from admin gateway (called from wire cleanup or shutdown)
func stopRegistration() {
	if globalRegClient != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := globalRegClient.Unregister(shutdownCtx); err != nil {
			log.Warnf("Failed to unregister from admin gateway: %v", err)
		}
		_ = globalRegClient.Close()
	}
}

// stopServices stops background services (called from wire cleanup)
func stopServices() {
	if globalScanExecutor != nil {
		if err := globalScanExecutor.Stop(); err != nil {
			log.Warnf("Failed to stop scan executor: %v", err)
		}
	}
}

func runApp() error {
	ctx := bootstrap.NewContext(
		context.Background(),
		&conf.AppInfo{
			Project: pkgService.Project,
			AppId:   "ipam.service",
			Version: version,
		},
	)

	// Ensure services are stopped on exit
	defer stopServices()
	defer stopRegistration()

	return bootstrap.RunApp(ctx, initApp)
}

func main() {
	if err := runApp(); err != nil {
		panic(err)
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

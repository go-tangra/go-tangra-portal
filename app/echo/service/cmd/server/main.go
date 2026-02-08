package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	"github.com/go-tangra/go-tangra-portal/app/echo/service/cmd/server/assets"
	"github.com/go-tangra/go-tangra-portal/app/echo/service/internal/registration"
	"github.com/go-tangra/go-tangra-portal/app/echo/service/internal/server"
	"github.com/go-tangra/go-tangra-portal/app/echo/service/internal/service"
)

var (
	// Module info
	moduleID    = "echo"
	moduleName  = "Echo Service"
	version     = "1.0.0"
	description = "A simple echo service for testing dynamic module registration"

	// Flags
	grpcAddr      string
	adminEndpoint string
)

func init() {
	flag.StringVar(&grpcAddr, "grpc-addr", getEnvOrDefault("GRPC_ADDR", "0.0.0.0:9500"), "gRPC server address")
	flag.StringVar(&adminEndpoint, "admin-endpoint", getEnvOrDefault("ADMIN_GRPC_ENDPOINT", "localhost:9000"), "Admin gateway gRPC endpoint")
}

func main() {
	flag.Parse()

	// Create logger
	logger := log.With(log.NewStdLogger(os.Stdout),
		"service", moduleID,
		"version", version,
	)
	logHelper := log.NewHelper(logger)

	logHelper.Infof("Starting %s v%s", moduleName, version)
	logHelper.Infof("gRPC address: %s", grpcAddr)
	logHelper.Infof("Admin endpoint: %s", adminEndpoint)

	// Create service
	echoService := service.NewEchoService(logger)

	// Create gRPC server
	grpcServer := server.NewGRPCServer(logger, echoService, &server.Config{
		Addr: grpcAddr,
	})

	// Create Kratos app
	app := kratos.New(
		kratos.Name(moduleID),
		kratos.Version(version),
		kratos.Server(grpcServer),
		kratos.Logger(logger),
	)

	// Create registration client with embedded OpenAPI spec
	regConfig := &registration.Config{
		ModuleID:          moduleID,
		ModuleName:        moduleName,
		Version:           version,
		Description:       description,
		GRPCEndpoint:      grpcAddr,
		AdminEndpoint:     adminEndpoint,
		OpenapiSpec:       assets.OpenApiData,
		ProtoDescriptor:   nil, // Will be populated when proto is compiled with descriptor set
		HeartbeatInterval: 30 * time.Second,
		RetryInterval:     5 * time.Second,
		MaxRetries:        3,
	}

	regClient, err := registration.NewClient(logger, regConfig)
	if err != nil {
		logHelper.Errorf("Failed to create registration client: %v", err)
		// Continue without registration - service will still work but won't be discovered
	}

	// Start the app in a goroutine
	go func() {
		if err := app.Run(); err != nil {
			logHelper.Errorf("Failed to run app: %v", err)
		}
	}()

	// Wait a bit for the server to start
	time.Sleep(2 * time.Second)

	// Register with admin gateway
	ctx := context.Background()
	if regClient != nil {
		if err := regClient.Register(ctx); err != nil {
			logHelper.Errorf("Failed to register with admin gateway: %v", err)
		} else {
			// Start heartbeat
			go regClient.StartHeartbeat(ctx)
		}
	}

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logHelper.Info("Shutting down...")

	// Unregister from admin gateway
	if regClient != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := regClient.Unregister(shutdownCtx); err != nil {
			logHelper.Errorf("Failed to unregister from admin gateway: %v", err)
		}
		_ = regClient.Close()
	}

	// Stop the app
	if err := app.Stop(); err != nil {
		logHelper.Errorf("Failed to stop app: %v", err)
	}

	logHelper.Info("Service stopped")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Ensure grpcServer implements grpc.Server
var _ *grpc.Server = (*grpc.Server)(nil)

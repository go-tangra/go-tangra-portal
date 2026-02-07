package health

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var insecure bool

// Command is the health command
var Command = &cobra.Command{
	Use:   "health",
	Short: "Check health of the LCM server",
	Long: `Check if the LCM server is healthy and accepting connections.

Example:
  lcm-client health
  lcm-client health --insecure
`,
	RunE: runHealth,
}

func init() {
	Command.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS verification")
}

func runHealth(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")

	fmt.Printf("Checking health of server '%s'...\n", serverAddr)

	// Connect to server (TLS without client cert for health check)
	conn, err := client.CreateTLSConnectionWithoutClientCert(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create health client
	healthClient := grpc_health_v1.NewHealthClient(conn)

	// Send health check
	resp, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	switch resp.Status {
	case grpc_health_v1.HealthCheckResponse_SERVING:
		fmt.Println("Server is healthy and serving requests.")
	case grpc_health_v1.HealthCheckResponse_NOT_SERVING:
		fmt.Println("Server is not serving requests.")
	case grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN:
		fmt.Println("Server health status unknown.")
	default:
		fmt.Printf("Unexpected health status: %v\n", resp.Status)
	}

	return nil
}
